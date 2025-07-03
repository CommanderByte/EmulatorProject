from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from emulator.core.abstract.irq.trigger_type import TriggerType

if TYPE_CHECKING:
    from emulator.core.emulator import Emulator

class InterruptSource(ABC):
    """
    Abstract base class for devices capable of raising IRQs.
    """

    @abstractmethod
    def get_irq_number(self) -> int:
        ...

    def get_trigger_type(self) -> Optional[TriggerType]:
        """
        Returns the IRQ trigger type for this source, if known.
        By default, None: defer to InterruptController default or override.
        """
        return None

    def raise_irq(self):
        emulator = getattr(self, "emulator", None)
        if emulator:
            irq = self.get_irq_number()
            emulator.bus.raise_irq(irq)
        else:
            print(f"[WARN] IRQ source {self} not attached to emulator.")

    def lower_irq(self):
        emulator = getattr(self, "emulator", None)
        if emulator:
            irq = self.get_irq_number()
            emulator.bus.lower_irq(irq)
        else:
            print(f"[WARN] IRQ source {self} not attached to emulator.")
