from emulator.core.abstract.io.io_device import IODevice
from emulator.core.abstract.irq.interrupt_source import InterruptSource
from emulator.core.abstract.mmio.mmio_device import MMIODevice
from emulator.core.abstract.reset.resettable_device import ResettableDevice


class ISADevice(IODevice, MMIODevice, InterruptSource, ResettableDevice):
    """
    Composite base class for devices that conform to the ISA device model.

    ISA devices typically use fixed I/O port ranges and/or MMIO regions,
    and may optionally raise interrupts or require resets.

    This class serves to clearly group together devices that are expected
    to be attached to an ISABus or similar legacy-compatible bus.
    """
    pass
