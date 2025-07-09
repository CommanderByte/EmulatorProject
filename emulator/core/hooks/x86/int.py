"""
Mixin for CPU interrupt hooks.
"""

from typing import Any, Callable
from unicorn.unicorn_const import UC_HOOK_INTR

from emulator.core import HookMixin


class InterruptHookMixin(HookMixin):
    def on_interrupt(
        self,
        callback: Callable[[Any, int, Any], Any],
        begin:    int = 1,
        end:      int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook CPU exceptions and IRQs in [begin, end].

        callback signature:
          def callback(uc, intno, user_data)
        - uc:      the Unicorn instance
        - intno:   the interrupt or exception number
        - user_data: whatever you passed here

        Return value from callback is ignored (interrupts always resume).
        """
        return self.add_hook(UC_HOOK_INTR, callback, user_data, begin, end)
