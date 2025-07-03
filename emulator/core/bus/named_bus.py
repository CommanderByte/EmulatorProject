from abc import ABC, abstractmethod


class NamedBus(ABC):
    """
    A minimal interface representing a generic named bus.
    """

    @abstractmethod
    def get_bus_type(self) -> str:
        """
        Returns a short identifier describing this bus type (e.g., 'mmio', 'io', 'irq').

        Useful for diagnostics, bus introspection, or registry logging.

        :return: A short string identifier.
        :rtype: str
        """
        pass
