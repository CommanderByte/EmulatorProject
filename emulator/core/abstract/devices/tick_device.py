from abc import abstractmethod, ABC


from abc import ABC, abstractmethod

class TickDevice(ABC):
    """
    Abstract base class for devices that maintain and update an internal state
    based on elapsed time.

    This class serves as a template for devices that operate on time-based
    state updates. Implementers must provide a concrete implementation of
    the `tick` method, which advances the device's state by a specified
    number of microseconds.
    """

    @abstractmethod
    def tick(self, delta_us: int):
        """
        Advances the device's internal state by the given number of microseconds.

        This method is expected to be called regularly by a scheduler or main
        emulator loop to allow the device to update internal timers, counters,
        or generate interrupts.

        :param delta_us: Time to advance, in microseconds.
        """
        ...
