# emulator/core/helpers/bar.py

class PCIBARAllocator:
    """
    Helper class to allocate BARs for a PCI device.

    This manages BAR index, layout, and updates the config space accordingly.
    """

    def __init__(self):
        self.next_bar_index = 0
        self.base_address = 0x8000_0000  # Starting point for emulated BAR MMIOs
        self.allocations = []  # List of (bar_index, base_addr, size, is_io)

    def allocate_bar(
        self,
        config_space: bytearray,
        size: int,
        is_io: bool = False,
        prefetchable: bool = False,
    ) -> int:
        """
        Allocate a BAR region and patch the PCI config space.

        :param config_space: PCI config space (bytearray) to patch.
        :param size: Number of bytes to allocate.
        :param is_io: True if I/O port BAR, False for MMIO.
        :param prefetchable: Only valid for MMIO.
        :return: The base address assigned to this BAR.
        """
        if self.next_bar_index >= 6:
            raise ValueError("All 6 BARs already used")

        bar_offset = 0x10 + self.next_bar_index * 4
        self.next_bar_index += 1

        # Align size to power-of-two
        aligned_size = 1 << (size - 1).bit_length()

        if is_io:
            # I/O BAR: lowest bit is 1
            base_addr = self.base_address & 0xFFFF_FFFC
            bar_value = base_addr | 0x1
        else:
            # Memory BAR: lowest 4 bits define type
            base_addr = self.base_address & 0xFFFF_FFF0
            bar_value = base_addr
            if prefetchable:
                bar_value |= 0x8  # Set PF bit

        # Patch config space
        config_space[bar_offset:bar_offset + 4] = bar_value.to_bytes(4, "little")

        # Bookkeeping
        self.allocations.append((bar_offset, base_addr, aligned_size, is_io))
        self.base_address += aligned_size

        return base_addr
