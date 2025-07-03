from abc import ABC
from typing import Any

class ConfigurableDevice(ABC):
    """
    Mixin to support runtime configuration of devices via key-value settings.
    """

    def apply_config(self, key: str, value: Any):
        """
        Apply a configuration setting to the device.
        Override to handle custom keys.

        :param key: Name of the config option
        :param value: Value to assign
        """
        raise NotImplementedError(f"Unknown config key: {key}")

    def get_config_schema(self) -> dict:
        """
        Optional method to declare what config keys are supported and expected types.
        """
        return {}
