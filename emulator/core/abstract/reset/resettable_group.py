from emulator.core.abstract.reset.resettable_device import ResettableDevice

class ResettableGroup(ResettableDevice):
    """
    A composite resettable device that holds and manages multiple other ResettableDevice instances.

    Use this to manage coordinated resets across a group of devices, like subsystems or chipsets.
    """

    def __init__(self):
        self._children: list[ResettableDevice] = []

    def add(self, device: ResettableDevice):
        """
        Adds a resettable device to the group.

        :param device: The resettable device to be managed by this group.
        """
        if not isinstance(device, ResettableDevice):
            raise TypeError(f"{device} is not a ResettableDevice")
        self._children.append(device)

    def reset(self):
        """
        Resets all attached devices in the group.
        """
        for device in self._children:
            device.reset()

    def __len__(self):
        return len(self._children)

    def __iter__(self):
        return iter(self._children)
