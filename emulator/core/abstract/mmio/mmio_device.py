from abc import ABC, abstractmethod
from typing import List

from emulator.core.abstract.mmio.mmio_range import MMIORange

class MMIODevice(ABC):
    """
    Represents an abstract base class for memory-mapped I/O (MMIO) devices.

    This class serves as a blueprint for defining MMIO devices. It enforces the
    implementation of methods for registering MMIO ranges that are critical for
    device functionality. Subclasses inheriting from this class must provide
    their own implementations for the abstract methods.

    :ivar mmio_ranges: A list of memory-mapped I/O ranges that belong to the device.
    :type mmio_ranges: List[MMIORange]
    """

    @abstractmethod
    def register_mmio_ranges(self) -> List[MMIORange]:
        """
        Abstract method to register Memory-Mapped I/O (MMIO) address ranges required by
        a specific implementation. This method must be implemented in a subclass to
        define the MMIO regions needed for an operation or device initialization.

        This process is essential for providing the necessary address ranges that
        enable communication between the application and hardware components.

        :raises NotImplementedError: If the subclass does not provide an implementation.

        :return: A list of `MMIORange` instances that describe the MMIO regions.
        :rtype: List[MMIORange]
        """
        pass
