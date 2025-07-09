"""
Mixin for debug register access hooks.
"""
# emulator/core/hooks/x86/debug.py

from typing import Any, Callable, List
from unicorn.unicorn_const import UC_HOOK_INSN
from unicorn.x86_const       import UC_X86_INS_MOV
from capstone                 import Cs, CS_ARCH_X86, CS_MODE_16
from capstone.x86_const       import (
    X86_OP_REG,
    X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3,
    X86_REG_DR4, X86_REG_DR5, X86_REG_DR6, X86_REG_DR7
)

from emulator.core import HookMixin

# map index → Capstone reg ID
_DR_REGS = {
    0: X86_REG_DR0, 1: X86_REG_DR1, 2: X86_REG_DR2, 3: X86_REG_DR3,
    4: X86_REG_DR4, 5: X86_REG_DR5, 6: X86_REG_DR6, 7: X86_REG_DR7,
}

class DebugRegisterHookMixin(HookMixin):
    def __init__(self, uc, *args, **kwargs):
        super().__init__(uc, *args, **kwargs)
        # disasm in 16-bit mode; switch to 32-bit if/when you flip modes
        self._dr_cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self._dr_cs.detail = True

    def on_dr_read(
        self,
        index: int,
        callback: Callable[[Any, int, Any], bool],
        begin:    int = 1,
        end:      int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook MOV r, DR{index} (reading from debug register).
        callback signature: (uc, index, user_data) -> bool
        """
        dr_id = _DR_REGS[index]

        def _cb(uc, user_data):
            pc   = uc.reg_read(uc.regs.EIP)
            code = uc.mem_read(pc, 6)             # read up to 6 bytes
            insns = list(self._dr_cs.disasm(code, pc, count=1))
            if not insns or insns[0].id != UC_X86_INS_MOV:
                return True

            insn = insns[0]
            ops  = insn.operands
            # MOV reg_dst, DRx → operand[1] is DRx
            if len(ops) == 2 \
            and ops[1].type == X86_OP_REG \
            and ops[1].reg  == dr_id:
                # user callback
                if not callback(uc, index, user_data):
                    return False
                # skip the instruction
                uc.reg_write(uc.regs.EIP, pc + insn.size)
            return True

        return self.add_hook(
            UC_HOOK_INSN, _cb, user_data, begin, end, UC_X86_INS_MOV
        )

    def on_dr_write(
        self,
        index: int,
        callback: Callable[[Any, int, int, Any], bool],
        begin:    int = 1,
        end:      int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook MOV DR{index}, r (writing to debug register).
        callback signature: (uc, index, value, user_data) -> bool
        """
        dr_id = _DR_REGS[index]

        def _cb(uc, user_data):
            pc   = uc.reg_read(uc.regs.EIP)
            code = uc.mem_read(pc, 6)
            insns = list(self._dr_cs.disasm(code, pc, count=1))
            if not insns or insns[0].id != UC_X86_INS_MOV:
                return True

            insn = insns[0]
            ops  = insn.operands
            # MOV DRx, reg_src → operand[0] is DRx
            if len(ops) == 2 \
            and ops[0].type == X86_OP_REG \
            and ops[0].reg  == dr_id:
                # read the new value from the src register
                src = ops[1]
