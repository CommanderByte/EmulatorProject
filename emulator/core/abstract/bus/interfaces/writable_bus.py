from abc import ABC, abstractmethod

class WritableBus(ABC):
    @abstractmethod
    def write(self, addr: int, data: bytes):
        """
        Write to the bus at the specified address.
        """
        ...