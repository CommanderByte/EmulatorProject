from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class PCICapability:
    capability_id: int
    next_pointer: int = 0
    payload: bytes = b''

    def total_length(self) -> int:
        return 2 + len(self.payload)

    def encode(self) -> bytes:
        return bytes([self.capability_id, self.next_pointer]) + self.payload



class PCICapabilityListBuilder:
    """
    Helps construct a valid PCI capability linked list.
    Automatically handles `next_pointer` assignment.
    """

    def __init__(self):
        self.capabilities: list[PCICapability] = []

    def add_capability(self, capability: PCICapability):
        self.capabilities.append(capability)

    def build(self) -> bytes:
        offset = 0
        for i, capability in enumerate(self.capabilities):
            next_offset = offset + capability.total_length() if i + 1 < len(self.capabilities) else 0
            capability.next_pointer = next_offset
            offset = next_offset

        return b''.join(c.encode() for c in self.capabilities)
