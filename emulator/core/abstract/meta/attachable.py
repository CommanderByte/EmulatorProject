from abc import ABC
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from emulator.core.emulator import Emulator
    from emulator.core.abstract.bus.bus_interface import BusInterface

class Attachable(ABC):
    """
    Mixin that allows a device or object to be attached to an emulator or bus.

    Provides standard fields and lifecycle hooks for initializing or resolving context
    once attached to a simulation environment.
    """

    emulator: Optional["Emulator"] = None
    bus: Optional["BusInterface"] = None

    def on_attach(self):
        """
        Optional hook called once the device is attached to an emulator/bus.
        Override in subclasses if needed.
        """
        pass

    def attach(self, emulator: "Emulator", bus: Optional["BusInterface"] = None):
        """
        Attach the device to an emulator and optional bus.

        :param emulator: The emulator instance managing the system
        :param bus: Optional bus to attach to
        """
        self.emulator = emulator
        self.bus = bus
        self.on_attach()
