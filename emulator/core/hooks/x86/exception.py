"""
Mixin for CPU exception and trap hooks.
"""
# emulator/core/hooks/exception.py

from unicorn.unicorn_const import (
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_PROT,
    UC_HOOK_MEM_WRITE_PROT,
    UC_HOOK_MEM_FETCH_PROT,
)
from .base import HookMixin

class ExceptionHookMixin(HookMixin):
    def on_mem_invalid(
        self,
        callback,
        begin:    int = 0,
        end:      int = 0xFFFFFFFF,
        user_data = None
    ) -> int:
        """
        Hook any *unmapped* memory read, write or fetch in [begin,end].
        Callback signature:
          callback(uc, access, address, size, value, user_data) -> bool
        Returns the single hook handle.
        """
        mask = (
            UC_HOOK_MEM_READ_UNMAPPED
          | UC_HOOK_MEM_WRITE_UNMAPPED
          | UC_HOOK_MEM_FETCH_UNMAPPED
        )
        return self.add_hook(mask, callback, user_data, begin, end)

    def on_mem_prot(
        self,
        callback,
        begin:    int = 0,
        end:      int = 0xFFFFFFFF,
        user_data = None
    ) -> int:
        """
        Hook any *protection* fault (read/write/fetch) in [begin,end].
        Callback signature:
          callback(uc, access, address, size, value, user_data) -> bool
        Returns the single hook handle.
        """
        mask = (
            UC_HOOK_MEM_READ_PROT
          | UC_HOOK_MEM_WRITE_PROT
          | UC_HOOK_MEM_FETCH_PROT
        )
        return self.add_hook(mask, callback, user_data, begin, end)
