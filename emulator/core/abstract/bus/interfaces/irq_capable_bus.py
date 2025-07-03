from abc import ABC, abstractmethod

class IRQCapableBus(ABC):
    @abstractmethod
    def raise_irq(self, irq: int):
        """
        Raise the specified IRQ.
        """
        ...

    @abstractmethod
    def lower_irq(self, irq: int):
        """
        Lower the specified IRQ.
        """
        ...