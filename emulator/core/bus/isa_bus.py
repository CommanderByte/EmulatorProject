from emulator.core.bus.io_bus import IOBus

class ISABus(IOBus):
    """
    ISA Bus — routes legacy I/O ports and optionally ISA-specific behavior.

    Currently inherits from IOBus without additional logic, but provides
    a semantic distinction for device registration, logging, and attachment.
    """

    def get_bus_type(self) -> str:
        return "isa"
