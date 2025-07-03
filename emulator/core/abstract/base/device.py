import logging
from abc import ABC
from dataclasses import dataclass
from threading import Lock
from typing import Optional, TYPE_CHECKING

from emulator.core.abstract.base.device_info import DeviceInfo

if TYPE_CHECKING:
    from emulator.core.emulator import Emulator

logger = logging.getLogger(__name__)



class Device(ABC):
    """Base class for attachable emulator devices.

    Devices provide optional hooks for bus integration and can be
    attached to an :class:`~emulator.core.emulator.Emulator` instance.

    Attributes
    ----------
    emulator : Optional[Emulator]
        Emulator this device is attached to, if any.
    info : DeviceInfo
        Metadata describing the device.
    """


    def __init__(self, name: Optional[str] = None, instance_id: Optional[str] = None,
                 description: Optional[str] = None):
        """Create device metadata.

        Parameters
        ----------
        name : Optional[str]
            User facing name for the device. Defaults to the class name.
        instance_id : Optional[str]
            Optional unique identifier for the device instance.
        description : Optional[str]
            Short description of the device.
        """
        self._lock = Lock()
        self.emulator: Optional["Emulator"] = None
        self.info = DeviceInfo(
            name=name or self.__class__.__name__,
            type=self.__class__.__name__,
            instance_id=instance_id,
            description=description
        )

    def attach(self, emulator: "Emulator") -> None:
        """Attach the device to an emulator.

        Parameters
        ----------
        emulator : Emulator
            The emulator instance this device should attach to.
        """
        with self._lock:
            if self.emulator is not None:
                logger.warning(f"⚠️ Device {self.__class__.__name__} is already attached.")
                return  # or raise an exception if strict

            self.emulator = emulator
            logger.debug(f"🔌 Attached device {self.__class__.__name__} to emulator.")
            self.on_attach()

    def detach(self) -> None:
        """Detach the device from the emulator."""
        with self._lock:
            if self.emulator is None:
                logger.warning(f"⚠️ Attempted to detach device {self.__class__.__name__}, but it is not attached.")
                return  # or raise an exception if strict

            logger.debug(f"🔌 Detached device {self.__class__.__name__} from emulator.")
            self.on_detach()
            self.emulator = None

    def on_attach(self) -> None:
        """Hook executed after :meth:`attach`.

        Subclasses may override this to perform device specific
        initialization once attached to an emulator.
        """
        pass

    def on_detach(self) -> None:
        """Hook executed after :meth:`detach`.

        Subclasses may override this to clean up resources when the
        device is detached from an emulator.
        """
        pass

    def get_emulator(self) -> Optional["Emulator"]:
        """Return the attached emulator if one is set.

        Returns
        -------
        Optional[Emulator]
            The emulator this device is attached to or ``None``.
        """
        with self._lock:
            return self.emulator

    def __str__(self) -> str:
        """Return a friendly identifier for the device."""
        return self.info.full_name()

    def __repr__(self) -> str:
        """Return a debug representation of the device."""
        return f"<{self.info.type} name='{self.info.full_name()}'>"

