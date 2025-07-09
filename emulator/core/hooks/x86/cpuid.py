"""
Mixin for CPUID instruction hooks.
"""
# emulator/core/hooks/x86/cpuid.py

from typing import Any, Callable
from unicorn.unicorn_const import UC_HOOK_INSN
from unicorn.x86_const     import UC_X86_INS_CPUID

from emulator.core import HookMixin


class CPUIDHookMixin(HookMixin):
    def on_cpuid(
        self,
        callback: Callable[[Any, Any], bool],
        begin:    int = 1,
        end:      int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook the CPUID instruction (all leaves).

        callback signature:
          def callback(uc, user_data) -> bool

        Return True to continue emulation, False to stop.

        Returns the hook handle.
        """
        return self.add_hook(
            UC_HOOK_INSN,
            callback,
            user_data,
            begin,
            end,
            UC_X86_INS_CPUID
        )

