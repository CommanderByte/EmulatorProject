# emulator/core/cpu/x86/generic.py
from typing import Tuple, Any

import capstone
from unicorn.unicorn_const import (
    UC_HOOK_INSN, UC_HOOK_CODE
)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_MODE_16
from capstone.x86_const import (
    X86_INS_IN, X86_INS_OUT,
    X86_INS_SYSCALL, X86_INS_SYSENTER,
    X86_INS_CPUID,
    X86_INS_MOV,
    X86_REG_CR0, X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR8,
    X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR6, X86_REG_DR7,
)

from emulator.core.cpu.base_cpu import CPU
from emulator.core.cpu.x86.state import x86CPUState
from emulator.core.event.x86.events import Event

class GenericX86CPU(CPU):
    """
    Generic x86 CPU model that publishes CPU_IN, CPU_OUT, CPU_SYSCALL,
    CPU_SYSENTER, CPU_CPUID via direct INS hooks, and publishes CODE_INSN
    for all other instructions via a CODE hook fallback.
    Subclasses and external components listen on the EventBus.
    """

    # instructions unicorn can hook directly
    _HOOKABLE: Tuple[int, ...] = (
        X86_INS_IN,
        X86_INS_OUT,
        X86_INS_SYSCALL,
        X86_INS_SYSENTER,
        X86_INS_CPUID,
    )

    def __init__(self, uc, hooks, event_bus=None, mode_64: bool = True):
        super().__init__(uc, hooks, event_bus)
        self.state = x86CPUState()
        # Capstone for CODE hook decoding
        mode = CS_MODE_64 if mode_64 else CS_MODE_32
        self._cs = Cs(CS_ARCH_X86, mode)

    def setup_hooks(self) -> None:
        # install direct INS hooks
        def _insn_cb(uc, insn, ud):
            evt = {
                X86_INS_IN:          Event.CPU_IN,
                X86_INS_OUT:         Event.CPU_OUT,
                X86_INS_SYSCALL:     Event.CPU_SYSCALL,
                X86_INS_SYSENTER:    Event.CPU_SYSENTER,
                X86_INS_CPUID:       Event.CPU_CPUID,
            }.get(insn.id)
            # publish returns list of handler results; stop if any False
            if evt:
                results = self.publish(evt, uc=uc, insn=insn)
                return all(results) if results else True
            return True

        # one hook for all HOOKABLE instructions
        self.hooks.add_hook(
            UC_HOOK_INSN,
            _insn_cb,
            priority=100,
            extra=self._HOOKABLE
        )

        _CR_REGS = {X86_REG_CR0, X86_REG_CR1, X86_REG_CR2, X86_REG_CR3,
                    X86_REG_CR4, X86_REG_CR8}
        _DR_REGS = {X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3,
                    X86_REG_DR6, X86_REG_DR7}

        # fallback for all other insns
        def _code_cb(uc, addr, size, ud):
            data = uc.mem_read(addr, size)
            for insn in self.disasm(data, addr):
                # 1) Detect MOV to/from control registers
                if insn.id == X86_INS_MOV and len(insn.operands) == 2:
                    op0, op1 = insn.operands
                    # MOV CRx, reg  or  MOV reg, CRx
                    if (op0.type == capstone.x86.X86_OP_REG and op0.reg in _CR_REGS) or \
                            (op1.type == capstone.x86.X86_OP_REG and op1.reg in _CR_REGS):
                        # publish a CONTROL_REGISTER event
                        if not all(self.publish(Event.CONTROL_REGISTER, uc=uc, insn=insn)):
                            return False
                        continue
                    # same for debug registers
                    if (op0.type == capstone.x86.X86_OP_REG and op0.reg in _DR_REGS) or \
                            (op1.type == capstone.x86.X86_OP_REG and op1.reg in _DR_REGS):
                        if not all(self.publish(Event.DEBUG_REGISTER, uc=uc, insn=insn)):
                            return False
                        continue

                # 2) …then your other unhookable cases…
                if insn.id not in self._HOOKABLE:
                    if not all(self.publish(Event.CODE_INSN, uc=uc, insn=insn)):
                        return False

            return True

        self.hooks.add_hook(
            UC_HOOK_CODE,
            _code_cb,
            priority=50
        )

        # base class may install additional hooks
        super().setup_hooks()

    def make_disassembler(self) -> Cs:
        mode_map = {16: CS_MODE_16, 32: CS_MODE_32, 64: CS_MODE_64}
        return Cs(CS_ARCH_X86, mode_map.get(self.bit_mode, CS_MODE_64))