from abc import ABC, abstractmethod

class DetachableBus(ABC):
    @abstractmethod
    def detach_device(self, device: object):
        """
        Detach a device from the bus.
        """
        ...