from abc import ABC
from typing import Optional


class NamedDevice(ABC):
    """
    Mixin that provides a name to a device or component.

    Useful for debugging, logging, configuration, and identification in systems
    where devices may be accessed by name.
    """

    def __init__(self, name: str = "", parent: Optional["NamedDevice"] = None):
        self.parent = Optional[NamedDevice] = parent
        self.name: str = name

    def set_name(self, name: str):
        """
        Set the device name.

        :param name: A human-readable string identifier.
        """
        self.name = name

    def get_name(self) -> str:
        """
        Return the name of the device.

        :return: The device name.
        """
        return self.name

    def set_parent(self, parent: "NamedDevice"):
        self.parent = parent

    def get_path(self) -> str:
        """
        Get full hierarchical path for the device (e.g., 'soc.usb.port1').

        :return: Dotted path from root to this device.
        """
        if not self.parent:
            return self.name
        return f"{self.parent.get_path()}.{self.name}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name or 'unnamed'}>"
