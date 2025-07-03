from abc import ABC
from typing import Any

class UserControllableDevice(ABC):
    """
    Mixin for devices controlled at runtime by the user (e.g., buttons, switches).
    """

    def set_input(self, key: str, value: Any):
        """
        Apply a user-facing input such as a toggle, button press, or knob twist.

        :param key: The name of the input
        :param value: The new value (bool, int, etc.)
        """
        raise NotImplementedError(f"Input '{key}' not supported")

    def get_inputs(self) -> dict:
        """
        Return current input values for all supported user controls.
        """
        return {}
