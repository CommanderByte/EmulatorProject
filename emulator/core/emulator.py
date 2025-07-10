import logging
from typing import Dict, Tuple, List, Optional, Any
from unicorn import Uc, UcError
from unicorn.unicorn_const import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_EIP

from .hooks.manager import HookManager
from .constants import DEFAULT_PERMISSIONS

class Emulator:
    """
    High-level wrapper around the Unicorn engine, with built-in logging
    and hook management.

    Attributes:
        unicorn (Uc): Underlying Unicorn engine instance.
        hook_manager (HookManager): Centralized hook registry.
        devices (List[Any]): Attached devices.
        memory_map (Dict[int, Tuple[int, int]]): Base->(size, perms).
        running (bool): True while emulation is active.
    """
    logger = logging.getLogger(__name__)

    def __init__(self,
                 arch: int,
                 mode: int,
                 bus: Optional[Any] = None
                ):
        self.logger.debug("Initializing Emulator: arch=%d, mode=%d", arch, mode)
        self.unicorn: Uc = Uc(arch, mode)
        self.hook_manager: HookManager = HookManager(self.unicorn)
        self.devices: List[Any] = []
        self.memory_map: Dict[int, Tuple[int, int]] = {}
        self.running: bool = False
        self.bus = bus

    def map_memory(self,
                   address: int,
                   size: int,
                   permissions: int = DEFAULT_PERMISSIONS,
                   content: bytes = b''
                  ) -> None:
        """
        Map a region of memory, write initial content, and log the action.
        """
        if address in self.memory_map:
            msg = f"Memory at 0x{address:X} already mapped"
            self.logger.error(msg)
            raise ValueError(msg)

        # map and optionally populate
        self.unicorn.mem_map(address, size, permissions)
        if content:
            self.unicorn.mem_write(address, content)
        self.memory_map[address] = (size, permissions)
        self.logger.debug(
            "Mapped memory 0x%X-%X perms=0x%X",
            address, address+size-1, permissions
        )

    def add_hook(self,
                 hook_type: int,
                 callback: Any,
                 **kwargs: Any
                ) -> int:
        """
        Register a Unicorn hook via HookManager and log the handle.
        """
        handle = self.hook_manager.add_hook(hook_type, callback, **kwargs)
        self.logger.debug(
            "Added hook handle=%d type=0x%X", handle, hook_type
        )
        return handle

    def remove_hook(self, handle: int) -> None:
        """
        Remove a registered hook and log the removal.
        """
        self.hook_manager.remove_hook(handle)
        self.logger.debug("Removed hook handle=%d", handle)

    def list_hooks(self) -> List[Dict[str, Any]]:
        """Return metadata for all active hooks."""
        return self.hook_manager.list_hooks()

    def clear_hooks(self) -> None:
        """Clear all registered hooks and log the action."""
        self.hook_manager.clear_all()
        self.logger.debug("Cleared all hooks")

    def run(self,
            start_address: int,
            end_address: int,
            timeout: int = 0
           ) -> None:
        """
        Start emulation, logging start and end, catching errors.
        """
        self.logger.info(
            "Starting emulation: 0x%X -> 0x%X", start_address, end_address
        )
        self.running = True
        try:
            # timeout=0 => run until end or hook stops it
            self.unicorn.emu_start(start_address, end_address, timeout=timeout)
        except UcError as e:
            self.logger.error("Emulation error: %s", e)
            raise
        finally:
            self.running = False
            self.logger.info("Emulation stopped at 0x%X",
                              self.unicorn.reg_read(UC_X86_REG_EIP))

    def reset(self) -> None:
        """Reset any resettable devices."""
        from .abstract.reset.resettable_group import ResettableGroup
        for dev in self.devices:
            if hasattr(dev, 'reset'):
                dev.reset()
        self.logger.debug("Devices reset")

    def tick(self) -> None:
        """Issue a single tick to all tickable devices."""
        for dev in self.devices:
            if hasattr(dev, 'tick'):
                dev.tick()
        self.logger.debug("Ticked devices")

    def clock(self, cycles: int = 1) -> None:
        """Clock all clocked devices for a number of cycles."""
        for i in range(cycles):
            self.tick()
        self.logger.debug("Clocked devices for %d cycle(s)", cycles)
