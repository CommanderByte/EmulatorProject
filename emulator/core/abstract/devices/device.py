import logging
from abc import ABC
from dataclasses import dataclass
from threading import Lock
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from emulator.core.emulator import Emulator

logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """
    Represents information about a device.

    The DeviceInfo class encapsulates details about a device, providing attributes
    such as its name, type, optional instance ID, and description. It also includes
    a method to generate a full name representation of the device, combining its
    name and instance ID if available.

    :ivar name: The name of the device.
    :type name: str
    :ivar type: The type of the device.
    :type type: str
    :ivar instance_id: An optional unique identifier for the device instance.
    :type instance_id: str or None
    :ivar description: An optional description of the device.
    :type description: str or None
    """
    name: str
    type: str
    instance_id: Optional[str] = None
    description: Optional[str] = None

    def full_name(self) -> str:
        """
        Generates the full name of an entity, optionally including an instance-specific
        identifier.

        This method creates a string representation of the entity's name. If the
        `instance_id` is provided, it appends the `instance_id` to the name in the
        format `name#instance_id`. If `instance_id` is not provided, only the name is
        returned.

        :return: A string representing the full name of the entity, optionally
            including the instance ID.
        :rtype: str
        """
        return f"{self.name}#{self.instance_id}" if self.instance_id else self.name

class Device(ABC):
    """
    Represents a base class for devices that interact with an emulator.

    This abstract base class outlines the common interface and lifecycle of devices
    that can attach to or detach from an emulator. It provides mechanisms for managing
    the state of attachment, optional hooks for extending behavior, and the ability to
    retrieve associated emulator information.

    :ivar _lock: Internal lock to synchronize attachment and detachment operations.
    :type _lock: threading.Lock
    :ivar emulator: The emulator instance to which the device is attached, or None if
        not attached.
    :type emulator: Optional[Emulator]
    :ivar info: Metadata about the device, such as its name, type, instance ID, and
        description.
    :type info: DeviceInfo
    """


    def __init__(self, name: Optional[str] = None, instance_id: Optional[str] = None,
                 description: Optional[str] = None):
        """
        Represents a device with basic information and an optional associated emulator.
        The class is initialized with parameters for its name, instance ID, and description.
        It internally sets up a thread lock for synchronization and stores device
        attributes like name, type, instance ID, and description.

        :param name: The name of the device. If not provided, defaults to the class name.
        :type name: Optional[str]

        :param instance_id: A unique identifier for the device instance. Optional.
        :type instance_id: Optional[str]

        :param description: A brief description of the device. Optional.
        :type description: Optional[str]
        """
        self._lock = Lock()
        self.emulator: Optional["Emulator"] = None
        self.info = DeviceInfo(
            name=name or self.__class__.__name__,
            type=self.__class__.__name__,
            instance_id=instance_id,
            description=description
        )

    def attach(self, emulator: "Emulator"):
        """
        Attaches the current device to the given emulator. Ensures thread safety
        and checks if the device is already attached. If the device is already attached,
        a warning is logged and the method returns without making changes. If the
        device is successfully attached, the on_attach callback is triggered.

        :param emulator: The emulator instance to attach the device to.
        :type emulator: Emulator
        :return: None
        """
        with self._lock:
            if self.emulator is not None:
                logger.warning(f"⚠️ Device {self.__class__.__name__} is already attached.")
                return  # or raise an exception if strict

            self.emulator = emulator
            logger.debug(f"🔌 Attached device {self.__class__.__name__} to emulator.")
            self.on_attach()

    def detach(self):
        """
        Detaches the device from its current emulator. This method ensures thread-safe
        operations using a lock. If the device is not attached to any emulator,
        a warning is logged. Upon successful detachment, the `on_detach` method
        is invoked, and the `emulator` attribute is set to None.

        :raises RuntimeError: If strict mode is enforced and the device is not attached
                              to any emulator when this method is invoked.
        """
        with self._lock:
            if self.emulator is None:
                logger.warning(f"⚠️ Attempted to detach device {self.__class__.__name__}, but it is not attached.")
                return  # or raise an exception if strict

            logger.debug(f"🔌 Detached device {self.__class__.__name__} from emulator.")
            self.on_detach()
            self.emulator = None

    def on_attach(self):
        """
        Method executed when an attachment action occurs. Intended to be overridden
        or customized by derived classes to define specific behavior when an
        attach operation is performed. This method currently does not contain
        any functionality.

        """
        pass

    def on_detach(self):
        """
        Handles the detachment logic for the current instance. This method is meant to be
        overridden in derived classes to perform any necessary cleanup or other operations
        when a detachment event occurs.

        :return: None
        :rtype: None
        """
        pass

    def get_emulator(self) -> Optional["Emulator"]:
        """
        Retrieves the current emulator instance in a thread-safe manner.

        This method uses a lock to ensure that the process of retrieving the emulator
        instance is thread-safe.

        :return: The current emulator instance if available, otherwise None.
        :rtype: Optional[Emulator]
        """
        with self._lock:
            return self.emulator

    def __str__(self):
        """
        Converts the object's data into a human-readable string representation.

        This method is used to provide a meaningful string representation of the object, serving as the output for functions such
        as `str()` or `print()`. It utilizes the provided `info` attribute's `full_name` method to form the basis of the
        representation.

        :return: A human-readable string representation of the object.
        :rtype: str
        """
        return self.info.full_name()

    def __repr__(self):
        """
        Generates a string representation of the object for debugging or logging purposes.

        :return: A string representing the object, including its type and full name.
        :rtype: str
        """
        return f"<{self.info.type} name='{self.info.full_name()}'>"

