from emulator.core.bus.io_bus import IOBus
from emulator.core.bus.mmio_bus import MMIOBus

class LPCBus(IOBus, MMIOBus):
    """
    Composed bus for LPC devices, combining IO and MMIO capabilities.

    LPCBus inherits behavior from both IOBus and MMIOBus,
    enabling it to handle legacy device mappings cleanly.
    """

    def __init__(self, name: str = "lpc"):
        super().__init__(name)

    def get_bus_type(self) -> str:
        return "lpc"
