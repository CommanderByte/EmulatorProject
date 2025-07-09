"""
Mixin for memory-access hooks.
"""

from unicorn.unicorn_const import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from .base import HookMixin

class MemoryHookMixin(HookMixin):
    def on_mem_read(
        self,
        callback,
        begin: int = 0,
        end:   int = 2**32 - 1,
        user_data=None
    ):
        """Hook memory reads in [begin, end]."""
        # manager.add_hook(self, hook_type, callback, user_data, begin, end)
        return self._hook_mgr.add_hook(UC_HOOK_MEM_READ, callback, user_data, begin, end)

    def on_mem_write(
        self,
        callback,
        begin: int = 0,
        end:   int = 2**32 - 1,
        user_data=None
    ):
        """Hook memory writes in [begin, end]."""
        return self._hook_mgr.add_hook(UC_HOOK_MEM_WRITE, callback, user_data, begin, end)

