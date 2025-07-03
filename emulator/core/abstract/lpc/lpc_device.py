from emulator.core.abstract.io.io_device import IODevice
from emulator.core.abstract.irq.interrupt_source import InterruptSource
from emulator.core.abstract.mmio.mmio_device import MMIODevice
from emulator.core.abstract.reset.resettable_device import ResettableDevice


class LPCDevice(IODevice, MMIODevice, InterruptSource, ResettableDevice):
    """
    Composite base class for devices that conform to the LPC (Low Pin Count) model.

    LPC devices are typically legacy peripherals mapped through Super I/O chips.
    They may use port I/O and/or MMIO and can raise IRQs.

    This class groups together common functionality for LPC-compatible devices.
    """
    pass
