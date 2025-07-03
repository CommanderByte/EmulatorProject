from dataclasses import dataclass


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