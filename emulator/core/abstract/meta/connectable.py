from abc import ABC
from typing import List, Optional, Callable, Any

class Connectable(ABC):
    """
    Mixin that allows devices to connect to one or more targets.

    Supports signal-style connectivity for devices that must propagate events or states.
    """

    def __init__(self):
        # Callbacks or devices this component is connected to
        self._connections: List[Any] = []
        self._on_connect: Optional[Callable[[Any], None]] = None

    def connect(self, target: Any):
        """
        Connect this device to another component or signal target.

        :param target: Any object (typically another Connectable or callback target)
        """
        self._connections.append(target)
        if self._on_connect:
            self._on_connect(target)

    def get_connections(self) -> List[Any]:
        """
        Return the list of currently connected targets.
        """
        return self._connections

    def set_on_connect(self, callback: Callable[[Any], None]):
        """
        Set a callback to be invoked whenever a new connection is made.

        :param callback: Callable accepting a single argument (the connected target)
        """
        self._on_connect = callback

    def disconnect(self, target: Any):
        """
        Disconnect a previously connected target.

        :param target: The object to disconnect from.
        """
        if target in self._connections:
            self._connections.remove(target)

    def clear_connections(self):
        """
        Remove all connections from this object.
        """
        self._connections.clear()
