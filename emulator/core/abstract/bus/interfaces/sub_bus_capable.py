from abc import ABC, abstractmethod

class SubBusCapable(ABC):
    @abstractmethod
    def add_sub_bus(self, name: str, bus: object):
        """
        Add a named sub-bus.
        """
        ...

    @abstractmethod
    def get_sub_bus(self, name: str) -> object:
        """
        Retrieve a named sub-bus.
        """
        ...