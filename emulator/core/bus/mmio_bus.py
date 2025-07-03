from typing import Union, List, Tuple
import logging

from emulator.core.abstract.bus.bus_participant import BusParticipant
from emulator.core.abstract.bus.interfaces.attachable_bus import AttachableBus
from emulator.core.abstract.bus.interfaces.detachable_bus import DetachableBus
from emulator.core.abstract.bus.interfaces.readable_bus import ReadableBus
from emulator.core.abstract.bus.interfaces.writable_bus import WritableBus
from emulator.core.abstract.mmio.mmio_device import MMIODevice, MMIORange
from emulator.core.bus.named_bus import NamedBus

logger = logging.getLogger(__name__)

class MMIOBus(NamedBus, BusParticipant, ReadableBus, WritableBus, AttachableBus, DetachableBus):
    """
    A bus responsible for handling memory-mapped I/O (MMIO) device access.

    It manages read and write operations on registered MMIO devices and their address ranges.
    """

    def on_bus_connect(self, bus: "Bus"):
        self.parent_bus = bus
        # Optionally: reserve a range in parent bus, acting as a "bridge"
        # e.g., parent_bus.register_mmio_device([(0xF000_0000, 0xF100_0000)], self)
        logger.debug(f"{self.name} connected to parent bus {bus.name}")

    def on_bus_disconnect(self):
        logger.debug(f"{self.name} disconnected from parent bus")
        self.parent_bus = None

    def get_bus_type(self) -> str:
        return "MMIO"

    def __init__(self):
        self.name = None
        self.parent_bus = None
        self.mmio_devices: List[Tuple[int, int, MMIODevice]] = []

    def attach_device(self, device: object):
        if isinstance(device, MMIODevice):
            for region in device.register_mmio_ranges():
                start, end = region.start, region.end()
                # Check for overlap
                for r_start, r_end, _ in self.mmio_devices:
                    if not (end <= r_start or start >= r_end):
                        raise ValueError(f"MMIO range 0x{start:08X}-0x{end - 1:08X} overlaps")
                self.mmio_devices.append((start, end, device))
                logger.info(f"📦 Registered MMIO {device.__class__.__name__} to 0x{start:08X}-0x{end - 1:08X}")

    def detach_device(self, device: object):
        before = len(self.mmio_devices)
        self.mmio_devices = [(s, e, d) for (s, e, d) in self.mmio_devices if d != device]
        after = len(self.mmio_devices)
        if before != after:
            logger.info(f"📤 Unregistered MMIO {device.__class__.__name__}")
        else:
            logger.warning(f"❌ Tried to unregister unknown MMIO device {device.__class__.__name__}")

    def read(self, addr: int, size: int = 1) -> bytes:
        for start, end, device in self.mmio_devices:
            if start <= addr < end:
                return device.on_mmio(addr, size, None, is_write=False)
        raise ValueError(f"MMIO read to unmapped address 0x{addr:08X}")

    def write(self, addr: int, data: bytes):
        for start, end, device in self.mmio_devices:
            if start <= addr < end:
                device.on_mmio(addr, len(data), data, is_write=True)
                return
        raise ValueError(f"MMIO write to unmapped address 0x{addr:08X}")
