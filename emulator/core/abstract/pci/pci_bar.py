from dataclasses import dataclass
from enum import Enum, auto


class BARType(Enum):
    MEMORY = auto()
    IO = auto()


@dataclass
class PCIBarRegion:
    bar_index: int
    bar_type: BARType
    address: int
    size: int
    prefetchable: bool = False

    def is_mmio(self) -> bool:
        return self.bar_type == BARType.MEMORY

    def is_io(self) -> bool:
        return self.bar_type == BARType.IO

    def mask(self) -> int:
        return 0xFFFFFFFC if not self.is_io else 0xFFFFFFFC

    def __repr__(self):
        bar_type = "MMIO" if self.is_mmio() else "I/O"
        pf = " (prefetchable)" if self.prefetchable and self.is_mmio() else ""
        return f"<BAR{self.bar_index}: {bar_type} @ 0x{self.address:X} ({self.size} bytes){pf}>"
