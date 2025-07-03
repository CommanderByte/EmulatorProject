from abc import ABC
from typing import Optional

from emulator.core.abstract.pci.pci_capabilities import PCICapability, PCICapabilityListBuilder


class PCIDevice(ABC):
    """
    A base implementation of a PCI-compliant device.
    """

    def __init__(self, bus: int = 0, device: int = 0, function: int = 0):
        self.bus = bus
        self.device = device
        self.function = function

        self.config_space = bytearray(PCI_CONFIG_SPACE_SIZE)
        self.capabilities: list[PCICapability] = []

        # Optional helpers for BAR management
        self.bar_allocator = PCI_BARAllocator()

        # Populate default header (can be overridden by subclass)
        self._initialize_config_header()

    def get_pci_address(self) -> tuple[int, int, int]:
        return (self.bus, self.device, self.function)

    def read_config(self, offset: int, size: int) -> int:
        data = self.config_space[offset:offset + size]
        return int.from_bytes(data, byteorder="little")

    def write_config(self, offset: int, size: int, value: int):
        value_bytes = value.to_bytes(size, byteorder="little")
        self.config_space[offset:offset + size] = value_bytes

        # Optional: handle BAR writes
        if 0x10 <= offset <= 0x24:
            bar_index = (offset - 0x10) // 4
            self._handle_bar_write(bar_index, value)

    def _initialize_config_header(self):
        # Standard PCI header fields — override in subclasses as needed
        self.config_space[0x00:0x02] = (0xFFFF).to_bytes(2, "little")  # Vendor ID (invalid by default)
        self.config_space[0x02:0x04] = (0xFFFF).to_bytes(2, "little")  # Device ID (invalid)
        self.config_space[0x0E] = 0x00  # Header type

    def add_capability(self, capability: PCICapability):
        self.capabilities.append(capability)

    def build_capability_list(self):
        builder = PCICapabilityListBuilder()
        for cap in self.capabilities:
            builder.add_capability(cap)
        capability_blob = builder.build()

        cap_pointer = 0x40  # First capability address (typical start)
        self.config_space[0x34] = cap_pointer  # Capability pointer

        self.config_space[cap_pointer:cap_pointer + len(capability_blob)] = capability_blob

    def allocate_bar(self, size: int, is_io: bool = False, prefetchable: bool = False) -> int:
        return self.bar_allocator.allocate_bar(self.config_space, size, is_io, prefetchable)

    def _handle_bar_write(self, bar_index: int, value: int):
        # This method can be used to trigger mapping of MMIO regions, e.g.
        # when the guest writes to the BAR during PCI enumeration
        print(f"[PCI] BAR{bar_index} written with 0x{value:08X}")
        # Subclasses can override this to map memory or I/O
