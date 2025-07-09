"""
Mixin for control register access hooks.
"""
# emulator/core/hooks/x86/cr.py

from typing import Any, Callable
from unicorn.unicorn_const import UC_HOOK_INSN
from unicorn.x86_const       import UC_X86_INS_MOV
from capstone                 import Cs, CS_ARCH_X86, CS_MODE_16
from capstone.x86_const import X86_OP_REG, X86_REG_CR0, X86_REG_CR1, \
    X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5, X86_REG_CR6, X86_REG_CR7, \
    X86_REG_CR8

from emulator.core import HookMixin

# map index → Capstone CR register ID
_CR_REGS = {
    0: X86_REG_CR0, 1: X86_REG_CR1, 2: X86_REG_CR2, 3: X86_REG_CR3,
    4: X86_REG_CR4, 5: X86_REG_CR5, 6: X86_REG_CR6, 7: X86_REG_CR7,
    8: X86_REG_CR8,
}

class ControlRegisterHookMixin(HookMixin):
    def __init__(self, uc, *args, **kwargs):
        super().__init__(uc, *args, **kwargs)
        # Disassembler in 16-bit mode; switch to 32/64 as needed
        self._cr_cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self._cr_cs.detail = True

    def on_cr_read(
        self,
        index: int,
        callback: Callable[[Any, int, Any], bool],
        begin:    int = 1,
        end:      int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook MOV reg, CR{index} (reading from control register).
        callback signature: (uc, index, user_data) -> bool
        """
        cr_id = _CR_REGS[index]

        def _cb(uc, user_data):
            pc   = uc.reg_read(uc.regs.EIP)
            code = uc.mem_read(pc, 6)                   # read up to 6 bytes
            insns = list(self._cr_cs.disasm(code, pc, count=1))
            if not insns or insns[0].id != UC_X86_INS_MOV:
                return True

            insn = insns[0]
            ops  = insn.operands
            # MOV dst, src — we want src to be CRx
            if (len(ops) == 2 and
                ops[1].type == X86_OP_REG and
                ops[1].reg  == cr_id):
                # invoke user callback
                if not callback(uc, index, user_data):
                    return False
                # skip the instruction
                uc.reg_write(uc.regs.EIP, pc + insn.size)
            return True

        # hook only MOV instructions
        return self.add_hook(
            UC_HOOK_INSN,
            _cb,
            user_data,
            begin,
            end,
            UC_X86_INS_MOV
        )

    def on_cr_write(
        self,
        index: int,
        callback: Callable[[Any, int, int, Any], bool],
        begin:    int = 1,
        end:      int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook MOV CR{index}, reg (writing to control register).
        callback signature: (uc, index, value, user_data) -> bool
        """
        cr_id = _CR_REGS[index]

        def _cb(uc, user_data):
            pc   = uc.reg_read(uc.regs.EIP)
            code = uc.mem_read(pc, 6)
            insns = list(self._cr_cs.disasm(code, pc, count=1))
            if not insns or insns[0].id != UC_X86_INS_MOV:
                return True

            insn = insns[0]
            ops  = insn.operands
            # MOV dst, src — we want dst to be CRx
            if (len(ops) == 2 and
                ops[0].type == X86_OP_REG and
                ops[0].reg  == cr_id):
                # extract the new value from the source register
                src = ops[1]
                val
