import logging
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING
from threading import Lock

if TYPE_CHECKING:
    from emulator.core.bus import Bus  # Forward declaration for type hinting

logger = logging.getLogger(__name__)

class BusParticipant(ABC):
    """
    Represents a participant that can connect to and disconnect from a system bus.

    This abstract base class is designed for devices or components interacting
    with a shared system bus. It provides mechanisms for managing the connection
    status and accessing the bus instance. Classes inheriting from this should
    implement the abstract methods to define behaviors when connected to or
    disconnected from the bus.

    :ivar _bus: The reference to the system bus instance. None if not connected.
    :type _bus: Optional[Bus]
    :ivar _bus_lock: A threading lock to ensure thread-safe access and modification
                     of the bus connection reference.
    :type _bus_lock: Lock
    """

    def __init__(self):
        """
        Represents the initialization of an object with a bus and a lock mechanism.

        This constructor initializes the private attributes `_bus` and `_bus_lock`.
        The `_bus` attribute is intended to store a reference to a `Bus` object,
        and `_bus_lock` serves as a threading lock to ensure thread safety.

        Attributes:
            _bus (Optional[Bus]): A reference to a `Bus` object or None.
            _bus_lock (Lock): A threading lock to control access to the `_bus` attribute.
        """
        self._bus: Optional["Bus"] = None
        self._bus_lock = Lock()

    @abstractmethod
    def on_bus_connect(self, bus: "Bus"):
        """
        Handles the event of connecting an object to a bus. This method should be
        implemented by all subclasses to define the specific behavior when a bus
        connection is established. It ensures thread-safe assignment of the bus
        object and logs the connection event.

        :param bus: The bus object to connect to.
        :type bus: "Bus"

        :raises NotImplementedError: This method must be implemented by subclasses.
        :return: None
        """
        with self._bus_lock:
            self._bus = bus
            logger.debug(f"🔌 {self.__class__.__name__} connected to bus.")

    @abstractmethod
    def on_bus_disconnect(self):
        """
        Handles the disconnection from the bus.

        This abstract method should be implemented to define behavior when a bus
        disconnection occurs. It acquires a lock to ensure thread safety, logs a
        disconnection message, and sets the bus reference to None.

        :raises NotImplementedError: if the subclass does not implement this method.
        """
        with self._bus_lock:
            logger.debug(f"🔌 {self.__class__.__name__} disconnected from bus.")
            self._bus = None

    def get_bus(self) -> Optional["Bus"]:
        """
        Retrieves the current bus instance protected by a lock.

        This method ensures thread-safe access to the `_bus` attribute
        by acquiring and releasing the `_bus_lock` during the operation.
        If no bus instance is assigned, the method returns ``None``.

        :rtype: Optional[Bus]
        :return: The current bus instance if assigned, otherwise ``None``.
        """
        with self._bus_lock:
            return self._bus
