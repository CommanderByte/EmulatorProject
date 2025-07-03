import logging
from typing import List

from emulator.core.abstract.devices.device import Device
from emulator.core.abstract.devices.mmio_device import MMIODevice, MMIORange

logger = logging.getLogger(__name__)

class MemoryMappedRAM(Device, MMIODevice):
    """
    Simple RAM device mapped through MMIO.

    Provides read-write access to a memory region.
    """

    def __init__(self, base_addr: int, size: int, zero_init: bool = True):
        super().__init__()
        self.base = base_addr
        self.size = size
        self.data = bytearray(size if zero_init else (b'\xFF' * size))

    def register_mmio_ranges(self) -> List[MMIORange]:
        return [MMIORange(start=self.base, length=self.size)]

    def on_mmio(self, mmio_address: int, size: int, value: int, is_write: bool):
        offset = mmio_address - self.base
        if offset + size > self.size:
            logger.error(f"❌ RAM access out of bounds: addr=0x{mmio_address:08X} size={size}")
            return 0

        if is_write:
            logger.debug(f"✍️ RAM write: addr=0x{mmio_address:08X} ← 0x{value:0{size*2}X}")
            self.data[offset:offset+size] = value.to_bytes(size, byteorder='little')
            return True
        else:
            value = int.from_bytes(self.data[offset:offset + size], byteorder='little')
            logger.debug(f"📖 RAM read: addr=0x{mmio_address:08X} → 0x{value:0{size*2}X}")
            return value
