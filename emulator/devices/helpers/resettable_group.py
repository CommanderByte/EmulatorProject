from emulator.core.abstract.reset.resettable_device import ResettableDevice


class ResettableGroup(ResettableDevice):
    def __init__(self):
        self._children: list[ResettableDevice] = []

    def add(self, device: ResettableDevice):
        self._children.append(device)

    def reset(self):
        for dev in self._children:
            dev.reset()
