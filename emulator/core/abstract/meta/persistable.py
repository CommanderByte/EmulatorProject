from abc import ABC

class PersistableDevice(ABC):
    """
    Mixin to allow saving and restoring device state (e.g., for save states).
    """

    def save_state(self) -> dict:
        """
        Serialize internal state to a dictionary.
        """
        return {}

    def load_state(self, state: dict):
        """
        Restore internal state from a saved dictionary.
        """
        pass
