from dataclasses import dataclass


@dataclass
class DeviceInfo:
    """Container describing a device.

    Attributes
    ----------
    name : str
        Display name of the device.
    type : str
        Device class or category.
    instance_id : Optional[str]
        Optional unique identifier used when multiple instances exist.
    description : Optional[str]
        Short textual description of the device.
    """
    name: str
    type: str
    instance_id: Optional[str] = None
    description: Optional[str] = None

    def full_name(self) -> str:
        """Return the name combined with ``instance_id`` if set.

        Returns
        -------
        str
            Full identifier for the device.
        """
        return f"{self.name}#{self.instance_id}" if self.instance_id else self.name