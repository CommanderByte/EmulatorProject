from abc import ABC, abstractmethod

class ReadableBus(ABC):
    @abstractmethod
    def read(self, addr: int, size: int = 1) -> bytes:
        """
        Read from the bus at the specified address.
        """
        ...