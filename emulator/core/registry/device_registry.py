import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class DeviceRegistry:
    """
    Registry for named devices within an emulator instance.

    Provides a consistent way to register, look up, and introspect devices using
    hierarchical path names like 'soc.uart0.tx'.

    This can be used for:
    - Logging and debugging
    - Automated test access
    - Command-line or UI control
    - Tree-based introspection

    Example:
        reg = DeviceRegistry()
        reg.register("soc.timer0", timer_dev)
        dev = reg.get("soc.timer0")
    """

    def __init__(self):
        self._devices: Dict[str, object] = {}

    def register(self, path: str, device: object):
        """
        Register a device at a given path.

        :param path: Hierarchical device path (e.g., "bus.uart0.rx")
        :param device: Device object to register
        :raises ValueError: If path is already registered
        """
        if path in self._devices:
            raise ValueError(f"Device already registered at path: {path}")
        self._devices[path] = device
        logger.debug(f"📌 Registered {device} at {path}")

    def get(self, path: str) -> Optional[object]:
        """
        Retrieve a device by its path.

        :param path: Full device path string
        :return: Device object or None if not found
        """
        return self._devices.get(path)

    def unregister(self, path: str):
        """
        Remove a registered device by path.

        :param path: Path to unregister
        """
        if path in self._devices:
            del self._devices[path]
            logger.debug(f"❌ Unregistered device at {path}")

    def all(self) -> Dict[str, object]:
        """
        Get a copy of the full device registry.

        :return: Mapping of path → device
        """
        return dict(self._devices)

    def clear(self):
        """
        Remove all entries from the registry.
        """
        logger.debug("🧹 Cleared device registry")
        self._devices.clear()
