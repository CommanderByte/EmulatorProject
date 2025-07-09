"""
Mixin for PCI configuration space hooks.
"""
from typing import Any, Callable, Union, Tuple
from unicorn.unicorn_const import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (
    UC_X86_INS_IN, UC_X86_INS_OUT
)

from emulator.core import HookMixin
from emulator.core.hooks.x86 import IOPortHookMixin

# Constants for the standard PCI config‐space I/O ports
_CFG_ADDR_PORT = 0xCF8
_CFG_DATA_PORT = 0xCFC

class PCIHookMixin(HookMixin, IOPortHookMixin):
    """
    Mixin to trap PCI config‐space accesses, either via a
    memory‐mapped window or via the legacy I/O ports (0xCF8/0xCFC).
    """

    # — memory‐mapped config space (unchanged) ———————————————

    def on_pci_mem_config_read(
        self,
        callback: Callable[[Any,int,int,int,int,int,Any], bool],
        bus:    int,
        slot:   int,
        func:   int,
        offset: Union[int,slice],
        user_data: Any = None
    ):
        """Hook reads to a MMIO PCI config region."""
        b,e = self._normalize_offset(offset)
        def _cb(uc, access, addr, size, value, ud):
            return callback(uc, bus, slot, func, addr, size, ud)
        return self.add_hook(UC_HOOK_MEM_READ, _cb, user_data, b, e)

    def on_pci_mem_config_write(
        self,
        callback: Callable[[Any,int,int,int,int,int,int,Any], bool],
        bus:    int,
        slot:   int,
        func:   int,
        offset: Union[int,slice],
        user_data: Any = None
    ):
        """Hook writes to a MMIO PCI config region."""
        b,e = self._normalize_offset(offset)
        def _cb(uc, access, addr, size, value, ud):
            return callback(uc, bus, slot, func, addr, size, value, ud)
        return self.add_hook(UC_HOOK_MEM_WRITE, _cb, user_data, b, e)

    @staticmethod
    def _normalize_offset(off: Union[int,slice]) -> Tuple[int,int]:
        if isinstance(off, slice):
            b = off.start or 0
            e = (off.stop - 1) if off.stop is not None else 0xFFFFFFFF
        else:
            b = e = off
        return b, e

    # — legacy I/O‐port‐based config space —————————————————————

    def on_pci_io_config(
        self,
        read_cb:  Callable[[Any,int,int,int,int,Any], int],
        write_cb: Callable[[Any,int,int,int,int,int,Any], bool],
        bus:    int,
        slot:   int,
        func:   int,
        user_data: Any = None
    ) -> Tuple[int,int,int]:
        """
        Hook the legacy 0xCF8/0xCFC I/O ports:
         1) trap OUT to 0xCF8 → latch the (bus,slot,func,offset)
         2) trap IN  from 0xCFC → call read_cb(uc,bus,slot,func,off,ud)
         3) trap OUT to 0xCFC → call write_cb(...)
        Returns a triple of handles (h_addr, h_data_in, h_data_out).
        """
        state = {"last_addr": 0}

        # 1) Address port writes (OUT  to 0xCF8)
        def _addr_cb(uc, port, value, ud):
            # value is the 32-bit config address
            state["last_addr"] = value
            return True

        h_addr = self.on_port_out(
            _CFG_ADDR_PORT, _addr_cb, user_data=user_data
        )

        # 2) Data port reads (IN  from 0xCFC)
        def _data_in_cb(uc, port, ud):
            cfg_addr = state["last_addr"]
            return read_cb(uc, bus, slot, func, cfg_addr, ud)

        h_data_in = self.on_port_in(
            _CFG_DATA_PORT, _data_in_cb, user_data=user_data
        )

        # 3) Data port writes (OUT to 0xCFC)
        def _data_out_cb(uc, port, value, ud):
            cfg_addr = state["last_addr"]
            return write_cb(uc, bus, slot, func, cfg_addr, value, ud)

        h_data_out = self.on_port_out(
            _CFG_DATA_PORT, _data_out_cb, user_data=user_data
        )

        return h_addr, h_data_in, h_data_out
