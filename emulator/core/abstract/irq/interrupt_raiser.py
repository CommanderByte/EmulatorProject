from abc import ABC, abstractmethod

class InterruptRaiser(ABC):
    """
    Interface for buses or systems that can raise or lower IRQs.

    Devices (typically InterruptSources) will call these methods to
    raise or lower specific IRQ lines via the connected bus.
    """

    @abstractmethod
    def raise_irq(self, irq: int):
        """
        Raise the specified IRQ line.
        """
        ...

    @abstractmethod
    def lower_irq(self, irq: int):
        """
        Lower the specified IRQ line.
        """
        ...
