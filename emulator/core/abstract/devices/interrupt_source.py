import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from emulator.core.emulator import Emulator

logger = logging.getLogger(__name__)

class InterruptSource(ABC):
    """
    Abstract base class representing an interrupt source in the system.

    This class defines the interface and basic behavior for components
    that can generate interrupt requests (IRQs) and interact with an emulator
    to assert or deassert interrupts in the system. Subclasses must implement
    the abstract method to provide IRQ number association.

    :ivar emulator: The emulator instance this interrupt source is
                    associated with, or None if not attached.
    :type emulator: Optional[Any]
    """

    @abstractmethod
    def get_irq_number(self) -> int:
        """
        Provides an interface for obtaining the Interrupt Request (IRQ) number
        relevant to a hardware device or software process.

        This abstract method should be implemented by subclasses to return the IRQ
        number. The IRQ number is an identifier for handling hardware or software
        interrupts within a system. Subclasses are expected to define the actual
        number based on their context.

        :raises NotImplementedError: if the method is not implemented by a subclass
        :return: Integer representing the IRQ number
        :rtype: int
        """
        ...

    def raise_irq(self):
        """
        Raises an interrupt request (IRQ) for the component, notifying the emulator if
        it is attached. Logs the appropriate messages during the process.

        If the current instance is attached to an emulator, this method retrieves the
        IRQ number from the component by calling its `get_irq_number` method, raises the
        IRQ through the emulator's bus, and logs the operation. If the component is not
        attached to an emulator, a warning message is logged.

        :raises: Does not explicitly raise an exception but logs a warning if the emulator
                 is not attached.
        :return: None
        """
        emulator = getattr(self, "emulator", None)
        if emulator:
            irq = self.get_irq_number()
            logger.debug(f"📣 Raising IRQ {irq} from {self.__class__.__name__}")
            emulator.bus.raise_irq(irq)
        else:
            logger.warning(f"⚠️ Cannot raise IRQ from {self.__class__.__name__}: not attached to emulator.")

    def lower_irq(self):
        """
        Lowers the interrupt request (IRQ) for the associated device, if the device is
        attached to an emulator. Logs the action or a warning if the operation cannot
        be performed due to the absence of an emulator.

        :param self: The instance of the class calling the method.
        :return: None
        """
        emulator = getattr(self, "emulator", None)
        if emulator:
            irq = self.get_irq_number()
            logger.debug(f"🔕 Lowering IRQ {irq} from {self.__class__.__name__}")
            emulator.bus.lower_irq(irq)
        else:
            logger.warning(f"⚠️ Cannot lower IRQ from {self.__class__.__name__}: not attached to emulator.")
