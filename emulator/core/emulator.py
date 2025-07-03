import logging
from typing import List, Tuple, Any, Callable, Dict

from unicorn import Uc, UC_PROT_NONE

from emulator.core.abstract.bus.bus_participant import BusParticipant
from emulator.core.abstract.base.device import Device
from emulator.core.abstract.reset.resettable_device import ResettableDevice
from emulator.core.abstract.time.tick_device import TickDevice
from emulator.core.bus import Bus
from emulator.core.hooks import HookManager

logger = logging.getLogger(__name__)

DEFAULT_PERMISSIONS = UC_PROT_NONE

class Emulator:
    """High level wrapper around the Unicorn engine.

    Attributes
    ----------
    unicorn : Uc
        Underlying Unicorn engine instance.
    hook_manager : HookManager
        Manages registered execution hooks.
    bus : Bus
        System bus used to connect devices.
    devices : List[Device]
        List of currently attached devices.
    hooks : List[Dict[str, Any]]
        Collection of Unicorn hooks added via :meth:`add_hook`.
    memory_map : Dict[int, Tuple[int, int]]
        Mapping of base address to ``(size, permissions)``.
    running : bool
        ``True`` while emulation is active.
    """

    def __init__(self, architecture: int, mode: int):
        """Initialize Unicorn and supporting structures.

        Parameters
        ----------
        architecture : int
            Unicorn architecture constant, e.g. ``UC_ARCH_X86``.
        mode : int
            Mode flag for the architecture, e.g. ``UC_MODE_32``.
        """
        self.unicorn = Uc(architecture, mode)
        self.hook_manager = HookManager(self.unicorn)
        self.bus = Bus(self)
        self.devices: List[Device] = []
        self.hooks: List[Dict[str, Any]] = []
        self.memory_map: Dict[int, Tuple[int, int]] = {}
        self.running = False

    def add_device(self, device: Device):
        """Attach ``device`` to the emulator and bus.

        Parameters
        ----------
        device : Device
            Device instance to attach.
        """
        device.attach(self)
        self.devices.append(device)

        if isinstance(device, BusParticipant):
            device.on_bus_connect(self.bus)

        # Bus will handle IODevice, MMIODevice, etc.
        self.bus.attach_device(device)

    def detach_device(self, device: Device):
        """Remove ``device`` from the emulator and bus.

        Parameters
        ----------
        device : Device
            The device instance to detach.
        """
        if device in self.devices:
            if isinstance(device, BusParticipant):
                device.on_bus_disconnect()

            self.bus.detach_device(device)

            self.devices.remove(device)
            device.detach()

    def is_device_attached(self, device: Device) -> bool:
        """Return ``True`` if ``device`` is attached.

        Parameters
        ----------
        device : Device
            The device to query.

        Returns
        -------
        bool
            ``True`` if the device is present.
        """
        return device in self.devices

    def map_memory(self, address: int, region_size: int, permissions: int = DEFAULT_PERMISSIONS, content: bytes = b""):
        """Map a region of memory and optionally populate ``content``.

        Parameters
        ----------
        address : int
            Base address for the region.
        region_size : int
            Size of the memory region in bytes.
        permissions : int, optional
            Unicorn permission flags. Defaults to ``DEFAULT_PERMISSIONS``.
        content : bytes, optional
            Data to write into the region after mapping.

        Raises
        ------
        ValueError
            If the address is already mapped.
        """
        if address in self.memory_map:
            raise ValueError(f"Memory at address {address:#x} is already mapped.")
        self._set_memory_map(address, region_size, permissions, content)
        self.memory_map[address] = (region_size, permissions)

    def _set_memory_map(self, address: int, region_size: int, permissions: int, content: bytes):
        """Internal helper to map memory and write ``content``.

        Parameters
        ----------
        address : int
            Start address for the region.
        region_size : int
            Size of the region in bytes.
        permissions : int
            Memory access flags.
        content : bytes
            Data to write after mapping.
        """
        if not isinstance(address, int) or not isinstance(region_size, int):
            raise TypeError("Address and region size must be integers.")
        if address < 0 or region_size <= 0:
            raise ValueError(f"Invalid address {address:#x} or region size {region_size}.")
        try:
            self.unicorn.mem_map(address, region_size, permissions)
        except Exception as e:
            logger.error(f"Memory mapping failed at {address:#x} with size {region_size}. Error: {e}")
        self._write_mem_content(address, content)

    def _write_mem_content(self, address: int, content: bytes):
        """Write ``content`` to ``address`` if provided.

        Parameters
        ----------
        address : int
            Destination address.
        content : bytes
            Data to write.
        """
        if content:
            self.unicorn.mem_write(address, content)

    def add_hook(self, hook_type: int, callback: Callable):
        """Register a Unicorn hook and track it.

        Parameters
        ----------
        hook_type : int
            Hook type constant from Unicorn.
        callback : Callable
            Function to invoke when the hook triggers.
        """
        self.unicorn.hook_add(hook_type, callback)
        self.hooks.append({"type": hook_type, "callback": callback})

    def run(self, start_address: int, end_address: int, instruction_count: int = 0):
        """Run the emulator between ``start_address`` and ``end_address``.

        Parameters
        ----------
        start_address : int
            Starting program counter value.
        end_address : int
            Stop address (exclusive).
        instruction_count : int, optional
            Maximum number of instructions to execute.
        """
        self.running = True
        self.unicorn.emu_start(start_address, end_address, count=instruction_count)

    def reset(self):
        """Reset all attached :class:`ResettableDevice` instances."""
        for device in self.devices:
            if isinstance(device, ResettableDevice):
                device.reset()

    def tick(self):
        """Issue a single tick to all :class:`TickDevice` instances."""
        for device in self.devices:
            if isinstance(device, TickDevice):
                device.tick(1)

    def clock(self, cycles: int = 1):
        """Clock all devices that provide a ``clock`` method.

        Parameters
        ----------
        cycles : int, optional
            Number of cycles to pass to each device, by default ``1``.
        """
        for device in self.devices:
            clock_method = getattr(device, "clock", None)
            if callable(clock_method):
                clock_method(cycles)
