from abc import ABC, abstractmethod

class AttachableBus(ABC):
    @abstractmethod
    def attach_device(self, device: object):
        """
        Attach a device to the bus.
        """
        ...