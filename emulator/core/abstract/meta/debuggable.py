from abc import ABC

class DebuggableDevice(ABC):
    """
    Mixin to provide a debug interface for devices.

    Devices can optionally expose internal state via `debug_state()`.
    """

    def debug_state(self) -> dict:
        """
        Return a dictionary representing the internal state of the device.
        Override in subclasses to expose meaningful debug info.

        :return: dict with keys and values representing state
        """
        return {}
