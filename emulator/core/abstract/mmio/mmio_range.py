from dataclasses import dataclass

@dataclass(frozen=True)
class MMIORange:
    """
    Represents a memory-mapped I/O (MMIO) range.

    Use this to define memory address space regions that MMIO devices will respond to.
    """
    start: int
    length: int

    def __post_init__(self):
        if self.length <= 0:
            raise ValueError(f"MMIORange must have positive length, got {self.length}")
        if self.start < 0:
            raise ValueError(f"MMIORange start address cannot be negative, got {self.start:#X}")

    @property
    def end(self) -> int:
        """
        Return the exclusive end address of the MMIO range.
        """
        return self.start + self.length

    def contains(self, addr: int) -> bool:
        """
        Check if a given address is within this MMIO range.
        """
        return self.start <= addr < self.end

    def overlaps(self, other: "MMIORange") -> bool:
        """
        Check if this range overlaps with another MMIORange.
        """
        return not (self.end <= other.start or self.start >= other.end)

    def __str__(self):
        return f"0x{self.start:X}-0x{self.end - 1:X} (size=0x{self.length:X})"
