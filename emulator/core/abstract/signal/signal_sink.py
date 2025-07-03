from abc import ABC, abstractmethod

class SignalSink(ABC):
    """
    Represents an abstract base class designed to handle incoming signals.

    This class defines the interface for receiving and processing signals emitted
    by a source. It must be subclassed, and the subclass should implement the
    abstract method to handle specific signal logic. It is useful in creating a
    dependency between signal sources and their handlers for custom processing.

    """

    @abstractmethod
    def on_signal(self, signal: str, value: int):
        """
        Handles a signal event and processes an associated value.

        This abstract method is intended to be overridden in derived classes
        to provide specific implementation for handling signals and their
        corresponding values. The method does not define behavior itself,
        but serves as a blueprint for subclasses to implement signal handling
        logic tailored to their requirements.

        :param signal: A string representing the signal identifier.
        :param value: An integer representing the signal's associated value.
        :return: None
        """
        ...
