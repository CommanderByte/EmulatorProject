from abc import ABC, abstractmethod
from threading import Lock
from typing import Dict, List

from emulator.core.abstract.signal.signal_sink import SignalSink


class SignalSource(ABC):
    """
    Represents an abstract base class for objects that emit signals to connected sinks.

    The purpose of this class is to provide a mechanism to manage connections between signals
    and sinks and to propagate emitted signals to all connected sinks. Subclasses must
    implement the `connect_sink` method to define how sinks are connected to specific signals.

    :ivar _sinks: A dictionary mapping signal names to a list of connected sinks.
    :type _sinks: Dict[str, List[SignalSink]]
    :ivar _signal_lock: A threading lock used to synchronize access to the sinks.
    :type _signal_lock: Lock
    """

    def __init__(self):
        self._sinks: Dict[str, List[SignalSink]] = {}
        self._signal_lock = Lock()

    @abstractmethod
    def connect_sink(self, sink: SignalSink, signal: str):
        """
        Connects a signal sink to a specific signal. The method stores the sink
        within an internal structure under the given signal, ensuring synchronized
        access to avoid data races.

        :param sink: Instance of SignalSink to be connected
        :param signal: Name of the signal to which the sink should subscribe
        :return: None
        """
        with self._signal_lock:
            self._sinks.setdefault(signal, []).append(sink)

    def emit_signal(self, signal: str, value: int):
        """
        Emit a signal to notify all registered sinks about the occurrence of a particular event with an associated value.

        This method sends an event, represented as a string signal, along with an integer value
        to all registered sinks that are subscribed to the given signal. It ensures thread safety
        by locking during the emission process.

        :param signal: The name of the signal/event to be emitted. Represents the type of event
            occurring.
        :param value: The integer value associated with the signal. Represents additional
            information or data related to the signal.
        :return: None
        """
        with self._signal_lock:
            for sink in self._sinks.get(signal, []):
                sink.on_signal(signal, value)
