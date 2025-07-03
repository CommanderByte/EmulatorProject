import logging
from emulator.core.abstract.devices.device import Device
from emulator.core.abstract.devices.io_device import IODevice
from emulator.core.abstract.devices.mmio_device import MMIODevice, MMIORange
from typing import List

logger = logging.getLogger(__name__)

class NoopDevice(Device, IODevice, MMIODevice):
    """
    A dummy device that silently ignores all I/O and MMIO accesses.
    Useful as a placeholder or test stub.
    """

    def register_io_ports(self) -> List[int]:
        return []

    def register_mmio_ranges(self) -> List[MMIORange]:
        return []

    def on_io(self, port: int, size: int, value: int, is_write: bool):
        op = "write" if is_write else "read"
        logger.debug(f"[NoopDevice] Ignored I/O {op} at port 0x{port:04X}, size={size}")
        return 0 if not is_write else True

    def on_mmio(self, address: int, size: int, value: int, is_write: bool):
        op = "write" if is_write else "read"
        logger.debug(f"[NoopDevice] Ignored MMIO {op} at 0x{address:08X}, size={size}")
        return 0 if not is_write else True
