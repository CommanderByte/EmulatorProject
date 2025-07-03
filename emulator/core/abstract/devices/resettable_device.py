from abc import ABC, abstractmethod

class ResettableDevice(ABC):
    """
    Represents an abstract base class for a resettable device.

    This class serves as a blueprint for devices that require a reset
    functionality. Any concrete subclass must implement the `reset`
    method. The main purpose is to ensure that all devices inheriting
    from this class can be reset to their initial state, clearing or
    reinitializing all internal states such as registers, buffers,
    and counters.
    """

    @abstractmethod
    def reset(self):
        """
        An abstract class method that enforces implementation for resetting
        the state of an object in a subclass. This method serves as a
        contract for child classes to define specific behavior for resetting
        or initializing their internal state.

        :raises NotImplementedError: If a subclass does not implement
            the method, calling it will result in this error being raised.
        """
        ...
