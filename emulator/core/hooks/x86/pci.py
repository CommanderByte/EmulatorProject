"""
Adapter for PCI MMIO config-space reads/writes.
"""
from typing import Tuple
from unicorn.unicorn_const import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

class PciHook:
    @staticmethod
    def register(
        hooks,
        read_handler,
        write_handler,
        *,
        priority_read: int = 0,
        priority_write: int = 0
    ) -> Tuple[int, int]:
        """
        Subscribe `read_handler` to MMIO reads and `write_handler` to MMIO writes.

        read_handler(uc, addr, size) -> int
        write_handler(uc, addr, size, value) -> None

        Returns:
            (read_handle, write_handle)
        """
        read_cb = lambda uc, access, addr, size, value, user_data: read_handler(uc, addr, size)
        write_cb = lambda uc, access, addr, size, value, user_data: write_handler(uc, addr, size, value)

        h_read = hooks.add_hook(
            UC_HOOK_MEM_READ,
            read_cb,
            priority=priority_read
        )
        h_write = hooks.add_hook(
            UC_HOOK_MEM_WRITE,
            write_cb,
            priority=priority_write
        )
        return (h_read, h_write)