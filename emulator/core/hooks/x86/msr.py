"""
Mixin for MSR read/write hooks.
"""
from unicorn.unicorn_const import UC_HOOK_INSN
from emulator.core.hooks.base import HookMixin

from typing import Any, Callable
from unicorn.unicorn_const import UC_HOOK_INSN
from unicorn.x86_const import UC_X86_INS_RDMSR, UC_X86_INS_WRMSR

class MSRMixin(HookMixin):
    def on_msr_read(
        self,
        msr_id: int,
        callback: Callable[[Any, int, Any], bool],
        begin:   int = 1,
        end:     int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook RDMSR for the given MSR ID (in ECX).
        callback signature: (uc, msr_id, user_data) -> bool
        """
        def _cb(uc, user_data):
            current = uc.reg_read(uc.regs.ECX)
            if current == msr_id:
                # invoke user callback
                return callback(uc, current, user_data)
            return True

        return self.add_hook(
            UC_HOOK_INSN,
            _cb,
            user_data,
            begin,
            end,
            UC_X86_INS_RDMSR
        )

    def on_msr_write(
        self,
        msr_id: int,
        callback: Callable[[Any, int, int, Any], bool],
        begin:   int = 1,
        end:     int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook WRMSR for the given MSR ID (in ECX).
        callback signature: (uc, msr_id, value, user_data) -> bool
        """
        def _cb(uc, user_data):
            current = uc.reg_read(uc.regs.ECX)
            if current == msr_id:
                # combine EDX:EAX into a 64-bit value
                low  = uc.reg_read(uc.regs.EAX)
                high = uc.reg_read(uc.regs.EDX)
                val  = (high << 32) | low
                return callback(uc, current, val, user_data)
            return True

        return self.add_hook(
            UC_HOOK_INSN,
            _cb,
            user_data,
            begin,
            end,
            UC_X86_INS_WRMSR
        )

