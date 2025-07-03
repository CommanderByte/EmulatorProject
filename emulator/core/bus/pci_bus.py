import logging

from emulator.core.abstract.bus.interfaces.attachable_bus import AttachableBus
from emulator.core.abstract.bus.interfaces.detachable_bus import DetachableBus
from emulator.core.abstract.pci.pci_device import PCIDevice

from emulator.core.abstract.bus.bus_participant import BusParticipant
from emulator.core.bus.named_bus import NamedBus

logger = logging.getLogger(__name__)

class PCIBus(NamedBus, AttachableBus, DetachableBus, BusParticipant):

    def on_bus_connect(self, bus: "Bus"):
        pass

    def on_bus_disconnect(self):
        pass

    def __init__(self, name: str = "pci"):
        super().__init__(name)
        self.devices: dict[tuple[int, int, int], PCIDevice] = {}

    def get_bus_type(self) -> str:
        return "pci"

    def attach_device(self, device: object):
        if isinstance(device, PCIDevice):
            bdf = device.get_pci_address()
            if bdf in self.devices:
                raise ValueError(f"❌ PCI device at {bdf} already registered!")
            self.devices[bdf] = device
            logger.info(f"🧩 Registered PCI device {device.__class__.__name__} at {bdf}")
        else:
            raise TypeError(f"Device {device} does not implement PCIDevice!")

    def detach_device(self, device: object):
        for k, v in list(self.devices.items()):
            if v == device:
                del self.devices[k]
                logger.info(f"🔌 Unregistered PCI device at {k}")
                return

    def read_config(self, bus: int, dev: int, fn: int, offset: int, size: int) -> int:
        device = self.devices.get((bus, dev, fn))
        if not device:
            raise ValueError(f"No PCI device at {bus:02X}:{dev:02X}.{fn}")
        return device.read_config(offset, size)

    def write_config(self, bus: int, dev: int, fn: int, offset: int, size: int, value: int):
        device = self.devices.get((bus, dev, fn))
        if not device:
            raise ValueError(f"No PCI device at {bus:02X}:{dev:02X}.{fn}")
        device.write_config(offset, size, value)

    def get_device(self, bus: int, dev: int, fn: int) -> PCIDevice | None:
        return self.devices.get((bus, dev, fn))
