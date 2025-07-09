"""
Mixin for 16-bit segment transfer hooks.
"""

from typing import Any, Callable, List
from unicorn.unicorn_const import UC_HOOK_INSN
from unicorn.x86_const import UC_X86_INS_CALL, UC_X86_INS_RET
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

from emulator.core import HookMixin


class SegmentMixin(HookMixin):
    def __init__(self, uc, *args, **kwargs):
        super().__init__(uc, *args, **kwargs)
        # one 16-bit-capable disassembler for callbacks
        self._seg_cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self._seg_cs.detail = True

    def on_segment_transfer(
        self,
        callback: Callable[[Any, int, int, int, Any], bool],
        begin:     int = 1,
        end:       int = 0,
        user_data: Any = None
    ) -> List[int]:
        """
        Hook every CALL and RET in 16-bit mode, but only invoke `callback`
        when it’s a *far* transfer (immediate segment form).

        callback signature: (uc, access, addr, size, user_data) -> bool

        Returns two handles: [h_call, h_ret].
        """
        handles: List[int] = []
        for insn in (UC_X86_INS_CALL, UC_X86_INS_RET):
            handles.append(self.add_hook(
                UC_HOOK_INSN,
                self._make_far_filter(callback),
                user_data,
                begin,
                end,
                insn
            ))
        return handles

    def _make_far_filter(self, user_cb):
        """
        Wrap the user's callback so it only fires on far‐form CALL/RET.
        """
        def _cb(uc, user_data):
            # PC points at the instruction
            pc = uc.reg_read(uc.regs.EIP)
            # read up to 6 bytes (far-return is one byte + 2-byte selector)
            code = uc.mem_read(pc, 6)
            insns = list(self._seg_cs.disasm(code, pc, count=1))
            if not insns:
                return True

            insn = insns[0]
            # far‐call/ret have exactly 2 immediate operands:
            if insn.id in (UC_X86_INS_CALL, UC_X86_INS_RET) \
            and len(insn.operands) == 2 \
            and insn.operands[0].type == insn.operands[1].type == 1:  # IMM
                # it’s a far transfer—invoke user callback
                # Unfortunately UC_HOOK_INSN gives us no addr/size, so pass them manually:
                return user_cb(uc, insn.address, insn.size, user_data)
            # else just continue
            return True

        return _cb
