import logging
from typing import List

from emulator.core.abstract.devices.device import Device
from emulator.core.abstract.devices.mmio_device import MMIODevice, MMIORange, BackedMMIODevice

logger = logging.getLogger(__name__)

class MemoryMappedROM(Device, BackedMMIODevice):
    """
    Simple ROM device mapped through MMIO.

    Provides read-only access to a fixed byte buffer.
    Writes are ignored or logged as warnings.
    """

    def __init__(self, base_addr: int, data: bytes):
        """
        Initializes an object with a specified base address, data, and calculates the size
        of the provided data in bytes.

        :param base_addr: An integer representing the base memory address.
        :type base_addr: int
        :param data: A sequence of bytes representing the associated data.
        :type data: bytes
        """
        super().__init__()
        self.base = base_addr
        self.data = data
        self.size = len(data)

    def register_mmio_ranges(self) -> List[MMIORange]:
        """
        Generates a list of memory-mapped I/O (MMIO) ranges for a specific base address
        and size. This function is typically used to configure or register memory
        regions for device communication or hardware interaction.

        :return: A list of MMIORange objects, where each object specifies the start
                 address and size of a memory-mapped I/O range.
        :rtype: List[MMIORange]
        """
        return [MMIORange(start=self.base, length=self.size)]

    def on_mmio(self, mmio_address: int, size: int, value: int, is_write: bool):
        """
        Handles memory-mapped I/O (MMIO) operations for a ROM object. This function manages
        read and write access to a specific memory region mapped by the ROM, ensuring
        operations stay within defined boundaries. For read operations, it fetches and returns
        data from the ROM, while write operations are logged and ignored, as ROM is
        typically read-only. Raises an error in cases where access is out of bounds.

        :param mmio_address: Address in the memory map where the operation is performed.
        :type mmio_address: int
        :param size: Number of bytes involved in the operation.
        :type size: int
        :param value: The value to be written during a write operation. Ignored during read.
        :type value: int
        :param is_write: Indicates whether the operation is a write operation (True) or
                         a read operation (False).
        :type is_write: bool
        :return: For read operations, returns the integer value read from the ROM at the
                 specified address and size. For write operations, always returns False.
        :rtype: int or bool
        """
        offset = mmio_address# - self.base
        if offset + size > self.size:
            logger.error(f"❌ ROM read out of bounds: addr=0x{mmio_address:08X} size={size}")
            return 0

        if is_write:
            logger.warning(f"🚫 Write to ROM ignored: addr=0x{mmio_address:08X} value=0x{value:08X}")
            return False

        slice_ = self.data[offset:offset + size]
        result = int.from_bytes(slice_, byteorder='little')
        logger.debug(f"📖 ROM read: addr=0x{mmio_address:08X} → 0x{result:0{size*2}X}")
        return result

    def get_backed_memory(self):
        """
        Retrieve a list of tuples representing the backed memory regions.

        This method returns a list containing tuples where each tuple consists
        of the base memory address and its associated data. It is designed to
        return the memory regions that are currently backed within the system.

        :return: A list of tuples. Each tuple contains the base memory address
                 and its corresponding data.
        :rtype: list[tuple[int, Any]]
        """
        return [(self.base, self.data)]

