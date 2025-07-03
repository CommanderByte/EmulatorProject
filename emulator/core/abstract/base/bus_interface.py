from abc import ABC, abstractmethod
from typing import Optional

class BusInterface(ABC):
    """
    Abstract interface for buses in the system.

    Devices or subsystems will interact with a bus via this interface, without depending
    on a specific bus implementation.
    """

    @abstractmethod
    def read(self, addr: int, size: int = 1) -> bytes:
        """
        Perform a memory-mapped or IO read from the bus.
        """
        ...

    @abstractmethod
    def write(self, addr: int, data: bytes):
        """
        Perform a memory-mapped or IO write to the bus.
        """
        ...

    @abstractmethod
    def raise_irq(self, irq: int):
        """
        Raise the specified interrupt line.
        """
        ...

    @abstractmethod
    def lower_irq(self, irq: int):
        """
        Lower the specified interrupt line.
        """
        ...

    @abstractmethod
    def attach_device(self, device: object):
        """
        Attach a device to the bus.
        """
        ...
