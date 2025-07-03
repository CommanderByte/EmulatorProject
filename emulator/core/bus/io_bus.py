import logging
from typing import Union, Optional

from emulator.core.abstract.bus.bus_participant import BusParticipant
from emulator.core.abstract.bus.interfaces.attachable_bus import AttachableBus
from emulator.core.abstract.bus.interfaces.detachable_bus import DetachableBus
from emulator.core.abstract.bus.interfaces.readable_bus import ReadableBus
from emulator.core.abstract.bus.interfaces.writable_bus import WritableBus
from emulator.core.abstract.io.port_range import PortRange
from emulator.core.abstract.io.io_device import IODevice
from emulator.core.bus.named_bus import NamedBus

logger = logging.getLogger(__name__)


class IOBus(NamedBus, BusParticipant, ReadableBus, WritableBus, AttachableBus, DetachableBus):
    """
    Bus for routing I/O port-based access (IN/OUT) to registered IODevices.
    """

    def on_bus_connect(self, bus: "Bus"):
        # No special behavior needed for now
        pass

    def on_bus_disconnect(self):
        # No special behavior needed for now
        pass

    def attach_device(self, device: object):
        if not isinstance(device, IODevice):
            return

        for pr in device.register_io_ports():
            start, end = pr.start, pr.end()
            for r_start, r_end, _ in self.io_ranges:
                if not (end <= r_start or start >= r_end):
                    raise ValueError(f"❌ I/O range 0x{start:04X}-0x{end - 1:04X} overlaps")
            self.io_ranges.append((start, end, device))
            logger.info(f"🔌 Registered {device.__class__.__name__} to I/O 0x{start:04X}-0x{end - 1:04X}")

    def detach_device(self, device: object):
        self.io_ranges = [
            (start, end, dev) for (start, end, dev) in self.io_ranges if dev != device
        ]
        logger.info(f"🛑 Detached {device.__class__.__name__} from I/O bus")

    def __init__(self, name: str = "io"):
        super().__init__(name)
        self.io_ranges: list[tuple[int, int, IODevice]] = []

    def get_bus_type(self) -> str:
        return "io"

    def read(self, port: int, size: int = 1) -> bytes:
        for start, end, dev in self.io_ranges:
            if start <= port < end:
                value = dev.on_io(port, size, None, is_write=False)
                return value.to_bytes(size, "little")
        raise ValueError(f"❌ Unmapped I/O read from 0x{port:04X}")

    def write(self, port: int, data: bytes):
        for start, end, dev in self.io_ranges:
            if start <= port < end:
                value = int.from_bytes(data, "little")
                dev.on_io(port, len(data), value, is_write=True)
                return
        raise ValueError(f"❌ Unmapped I/O write to 0x{port:04X}")

    def get_device_for_port(self, port: int) -> Optional[IODevice]:
        for start, end, dev in self.io_ranges:
            if start <= port < end:
                return dev
        return None
