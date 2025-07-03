import logging
from collections import defaultdict
from threading import Lock
from typing import Any, Optional, Union

from unicorn import (
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_INSN, UC_MEM_WRITE_UNMAPPED
)

from emulator.core.abstract.devices.bus_participant import BusParticipant
from emulator.core.abstract.devices.clocked_device import ClockedDevice
from emulator.core.abstract.devices.dma_controller import DMAController
from emulator.core.abstract.devices.interrupt_controller import InterruptController
from emulator.core.abstract.devices.io_device import IODevice
from emulator.core.abstract.devices.mmio_device import MMIODevice, MMIORange, CallbackMMIODevice, BackedMMIODevice
from emulator.core.abstract.devices.resettable_device import ResettableDevice
from emulator.core.abstract.devices.signal_sink import SignalSink
from emulator.core.abstract.devices.signal_source import SignalSource
from emulator.core.abstract.devices.tick_device import TickDevice

logger = logging.getLogger(__name__)

class Bus:
    """
    Represents a system bus for managing communication and interaction between
    various devices in an emulated environment.

    The Bus class is responsible for registering and managing devices that
    use memory-mapped I/O (MMIO), standard I/O ports, signaling, and other
    functionalities such as Direct Memory Access (DMA) or interrupt handling.
    It also provides hooks for memory and I/O access within the emulator.

    :ivar emulator: Emulator instance managing this bus.
    :ivar _lock: Internal locking mechanism for thread-safe device operations.
    :ivar io_ranges: List of registered I/O ranges and their corresponding devices.
    :ivar mmio_devices: List of registered memory-mapped I/O ranges and devices.
    :ivar tick_devices: List of devices requiring periodic ticks.
    :ivar clocked_devices: List of devices operating with clock cycles.
    :ivar resettable_devices: List of devices supporting state reset.
    :ivar signal_sources: List of devices that act as signal sources.
    :ivar signal_sinks: List of devices that receive signals.
    :ivar dma_controller: Instance of the DMAController managing DMA operations,
        or None if not present.
    :ivar interrupt_controller: Instance of the InterruptController managing
        interrupt requests, or None if not present.
    """
    def __init__(self, emulator):
        """
        Represents a central management system for handling devices, memory-mapped I/O (MMIO), and
        various controllers within an emulator. This class is responsible for managing device
        registration, MMIO hooks, and I/O access within the emulator's environment.

        Attributes
        ----------
        emulator : Any
            The emulator instance this class interacts with.
        _lock : Lock
            A threading lock to ensure thread-safe operations.
        io_ranges : list
            A list of registered I/O ranges.
        mmio_devices : list
            A list of registered MMIO devices.
        tick_devices : list
            A list of devices that require periodic tick updates.
        clocked_devices : list
            A list of devices synchronized with a clock source.
        resettable_devices : list
            A list of devices that support a reset mechanism.
        signal_sources : list
            A list of signal-producing devices or components.
        signal_sinks : list
            A list of signal-consuming devices or components.
        dma_controller : Optional[DMAController]
            A direct memory access (DMA) controller instance, if applicable.
        interrupt_controller : Optional[InterruptController]
            An interrupt controller instance, if applicable.

        :param emulator: The emulator object that integrates the device and I/O management system.
        :type emulator: Any
        """
        self.emulator = emulator
        self._lock = Lock()
        self.io_ranges = []
        self.mmio_devices = []

        self.tick_devices = []
        self.clocked_devices = []
        self.resettable_devices = []
        self.signal_sources = []
        self.signal_sinks = []

        self.dma_controller: Optional[DMAController] = None
        self.interrupt_controller: Optional[InterruptController] = None

        # Setup MMIO and I/O hooks into Unicorn
        self.emulator.hook_manager.add_hook(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
            self._handle_mmio_unmapped
        )
        self.emulator.hook_manager.add_hook(
            UC_HOOK_INSN,
            self._handle_io_access
        )

    def attach_device(self, device):
        """
        Attaches a given device to the system by registering it with the appropriate
        device-specific categories. Handles multiple types of devices and integrates
        them into the system depending on their function, such as IO, memory-mapped IO,
        clocking, signaling, DMA, and interrupt handling. This method ensures proper
        integration of devices while managing concurrency through locking.

        :param device: The device to be attached. It must be an instance of supported
            device types such as IODevice, MMIODevice, TickDevice, ClockedDevice,
            ResettableDevice, SignalSource, SignalSink, DMAController,
            InterruptController, or BusParticipant.
        :return: None
        """
        with self._lock:
            if isinstance(device, IODevice):
                self.register_io_device(device.register_io_ports(), device)
            if isinstance(device, MMIODevice):
                self.register_mmio_device(device.register_mmio_ranges(), device)
            if isinstance(device, TickDevice):
                self.tick_devices.append(device)
            if isinstance(device, ClockedDevice):
                self.clocked_devices.append(device)
            if isinstance(device, ResettableDevice):
                self.resettable_devices.append(device)
            if isinstance(device, SignalSource):
                self.signal_sources.append(device)
            if isinstance(device, SignalSink):
                self.signal_sinks.append(device)
            if isinstance(device, DMAController):
                self.dma_controller = device
            if isinstance(device, InterruptController):
                self.interrupt_controller = device
            if isinstance(device, BusParticipant):
                device.on_bus_connect(self)

    def detach_device(self, device):
        """
        Detaches a specified device from various internal lists that define the relationships
        and roles of devices in the current system. Updates internal structures to ensure
        the device is fully disconnected, including removing it from lists such as I/O ranges,
        memory-mapped devices, tick devices, and other relevant device categories. Additionally,
        handles special cases for specific device roles such as DMA controller or interrupt
        controller. If the device is a BusParticipant, its disconnection from the
        bus will be handled as well.

        :param device: The device object to be detached.
        :return: None
        """
        with self._lock:
            self.io_ranges = [(s, e, d) for (s, e, d) in self.io_ranges if d != device]
            self.mmio_devices = [(s, e, d) for (s, e, d) in self.mmio_devices if d != device]
            self.tick_devices = [d for d in self.tick_devices if d != device]
            self.clocked_devices = [d for d in self.clocked_devices if d != device]
            self.resettable_devices = [d for d in self.resettable_devices if d != device]
            self.signal_sources = [d for d in self.signal_sources if d != device]
            self.signal_sinks = [d for d in self.signal_sinks if d != device]

            if self.dma_controller == device:
                self.dma_controller = None
            if self.interrupt_controller == device:
                self.interrupt_controller = None

            if isinstance(device, BusParticipant):
                device.on_bus_disconnect()

    def register_io_device(self, ports_or_ranges: list[Union[int, tuple[int, int]]], device):
        """
        Registers an input/output (I/O) device for specified ports or port ranges.

        This method assigns a device to one or more I/O ports or ranges of ports.
        If a port or port range overlaps with an already registered range, a
        ValueError will be raised. Successful registration logs a message indicating
        the device and its assigned port range(s).

        :param ports_or_ranges: A list of ports or ranges of ports to which
            the device should be registered. Each entry can either be an integer,
            indicating a single port, or a tuple of two integers, representing
            a start and end port (inclusive of start and exclusive of end).
        :param device: The device to be registered to the specified ports or port
            ranges. The device is expected to have a properly initialized class.
        :return: None
        :raises ValueError: If any given port or port range overlaps with an
            already registered I/O range.
        """
        for entry in ports_or_ranges:
            start, end = (entry, entry + 1) if isinstance(entry, int) else entry
            for r_start, r_end, _ in self.io_ranges:
                if not (end <= r_start or start >= r_end):
                    raise ValueError(f"I/O range 0x{start:04X}-0x{end - 1:04X} overlaps")
            self.io_ranges.append((start, end, device))
            logger.info(f"🔌 Registered IO {device.__class__.__name__} to 0x{start:04X}-0x{end - 1:04X}")

    def register_mmio_device(self, regions: list[Union[int, tuple[int, int], MMIORange]], device):
        """
        Registers a memory-mapped I/O (MMIO) device and associates it with the specified memory
        regions. This method ensures that the specified regions do not overlap with existing
        registered regions and attaches the device to the system.

        :param regions: The list of memory regions to be registered with the device. Each region
            can be defined as an integer (representing a single address), a tuple specifying
            a range (start address and end address), or an MMIORange object encapsulating
            the range.
        :param device: The device to be registered to the specified memory regions. The device
            will be associated with these regions and any relevant callbacks will be
            initialized for system interaction.
        :return: None
        """
        for entry in regions:
            if isinstance(entry, MMIORange):
                start, end = entry.start, entry.end()
            elif isinstance(entry, int):
                start, end = entry, entry + 1
            else:
                start, end = entry

            for r_start, r_end, _ in self.mmio_devices:
                if not (end <= r_start or start >= r_end):
                    raise ValueError(f"MMIO range 0x{start:08X}-0x{end - 1:08X} overlaps")

            self.mmio_devices.append((start, end, device))
            logger.info(f"📦 Registered MMIO {device.__class__.__name__} to 0x{start:08X}-0x{end - 1:08X}")

        self._register_mmio_callbacks(device)

    def _register_mmio_callbacks(self, device: MMIODevice):
        """
        Registers memory-mapped I/O (MMIO) callbacks for the specified device. Depending on the type
        of the device passed, it either maps callback-based MMIO ranges or directly maps and writes
        to memory for backed memory devices.

        This function differentiates between `CallbackMMIODevice` and `BackedMMIODevice`. For
        `CallbackMMIODevice`, it registers read and write callbacks for specified MMIO regions.
        For `BackedMMIODevice`, it maps memory addresses and writes the associated buffer contents
        into them. Logging is used for debugging and tracking the operation.

        :param device: The MMIODevice instance for which the MMIO callbacks or memory mappings are to
                       be registered.
        :type device: MMIODevice
        :return: None
        """
        if isinstance(device, CallbackMMIODevice):
            for region in device.register_mmio_ranges():
                read_cb, read_ud, write_cb, write_ud = device.get_mmio_callbacks()
                self.emulator.unicorn.mmio_map(
                    region.start, region.length,
                    read_cb, read_ud,
                    write_cb, write_ud
                )
                logger.debug(f"🔧 MMIO callbacks registered for {device.__class__.__name__} at 0x{region.start:08X}")
        elif isinstance(device, BackedMMIODevice):
            for addr, buf in device.get_backed_memory():
                self.emulator.unicorn.mem_map(addr, len(buf))
                self.emulator.unicorn.mem_write(addr, buf)
                logger.debug(f"🗄️ Memory mapped for {device.__class__.__name__} at 0x{addr:08X} ({len(buf)} bytes)")

    def process_io_operation(self, port: int, size: int, value: int | None, is_write: bool):
        """
        Processes an I/O operation by determining the appropriate device for the given
        port and invoking its on_io method.

        This function iterates through the defined I/O ranges to find a range
        encompassing the specified port. If a matching range is found, it delegates
        the operation to the device associated with the respective range.

        :param port: The I/O port for the operation.
        :param size: The size of the data for the operation.
        :param value: The value to be written during the operation, or None if it is
            a read operation.
        :param is_write: A flag indicating whether the operation is a write (True)
            or a read (False).
        :return: The result of the on_io method from the matching device, or False if
            no matching range is found.
        """
        for start, end, device in self.io_ranges:
            if start <= port < end:
                return device.on_io(port, size, value, is_write)
        return False

    def process_mmio_operation(self, addr: int, size: int, value: int, is_write: bool):
        """
        Processes a memory-mapped I/O (MMIO) operation by determining if the provided
        address falls within the range of any registered MMIO device. If a matching
        device is found, delegates the MMIO operation to the device's `on_mmio`
        method. Otherwise, returns False to indicate no device was accessed.

        :param addr: The memory address the MMIO operation targets.
        :param size: The size of the MMIO operation in bytes.
        :param value: The data value involved in the MMIO operation. This could be
                      a value to write (if `is_write` is True) or ignored during
                      a read operation.
        :param is_write: A boolean flag indicating whether the operation is a write
                         (True) or a read (False).
        :return: True if the operation is successfully handled by a device's `on_mmio`
                 method, otherwise False if no device matches the provided address.
        """
        for start, end, device in self.mmio_devices:
            if start <= addr < end:
                return device.on_mmio(addr, size, value, is_write)
        return False

    def _handle_mmio_unmapped(self, uc, access, addr, size, value, user_data):
        """
        Handles memory-mapped input/output (MMIO) operations for unmapped memory regions.

        The method is invoked when an MMIO operation occurs in an unmapped memory address
        range, such as reads or writes to addresses that are not associated with existing
        memory mappings. It logs the MMIO access details, determines the type of operation
        (read/write), and delegates handling to the `process_mmio_operation` method.

        :param uc: The instance of the Unicorn emulation engine managing memory access.
        :param access: Indicates the type of access, typically `UC_MEM_WRITE_UNMAPPED` for
                       write operations or similar constants for other access types.
        :param addr: The memory address accessed during the MMIO operation.
        :param size: The size of the access in bytes.
        :param value: The value being written to memory in the case of an MMIO write operation.
        :param user_data: User-provided data or context relevant to the MMIO handling process.
        :return: Boolean value indicating whether the MMIO operation was successfully handled.
        :rtype: bool
        """
        is_write = access == UC_MEM_WRITE_UNMAPPED
        logger.debug(f"🧩 MMIO intercepted at 0x{addr:08X} (size={size}, write={is_write})")
        handled = self.process_mmio_operation(addr, size, value, is_write)
        return handled

    def _handle_io_access(self, uc, port, size, value, direction, user_data):
        """
        Handles input/output (I/O) access operations triggered by the given parameters. The method determines
        whether the operation is an input (IN) or output (OUT), logs the direction of the I/O operation,
        and delegates the further handling of the operation to the `process_io_operation` method.

        :param uc: The Unicorn Engine instance that triggered the I/O access.
        :type uc: Any
        :param port: The port on which the I/O access operation occurs.
        :type port: int
        :param size: The size (in bytes) of the data involved in the I/O operation.
        :type size: int
        :param value: The value being passed during the I/O operation.
        :type value: int
        :param direction: The direction of the I/O access; `0` for IN, `1` for OUT.
        :type direction: int
        :param user_data: Additional user-specific data associated with the I/O operation.
        :type user_data: Any
        :return: Result processed by the `process_io_operation` for the given I/O access.
        :rtype: Any
        """
        is_write = direction == 1  # 0 = IN, 1 = OUT
        logger.debug(f"🔌 I/O {'OUT' if is_write else 'IN '} on port 0x{port:04X} (size={size})")
        return self.process_io_operation(port, size, value, is_write)

    def raise_irq(self, irq: int):
        """
        Raises an interrupt request (IRQ) to the interrupt controller, if one is present.

        This function attempts to raise the specified IRQ by interacting with the
        interrupt controller associated with the instance. It does nothing if there
        is no interrupt controller.

        :param irq: The interrupt request number to be raised.
        :type irq: int
        """
        if self.interrupt_controller:
            self.interrupt_controller.raise_irq(irq)

    def lower_irq(self, irq: int):
        """
        Lowers the specified interrupt request (IRQ) through the associated interrupt
        controller. If the interrupt controller is not set, the method will not perform
        any action.

        :param irq: The integer representation of the interrupt request to be lowered.
        :type irq: int

        :return: None
        """
        if self.interrupt_controller:
            self.interrupt_controller.lower_irq(irq)

    def dma_transfer(self, *args, **kwargs):
        """
        Performs a Direct Memory Access (DMA) transfer by leveraging the associated
        DMA controller if available.

        This method checks if a DMA controller instance is present, and if so, delegates
        the transfer operation to the `dma_transfer` method of the DMA controller. If no
        DMA controller is available, the method returns None.

        :param args: Positional arguments to be passed to the DMA controller's
            `dma_transfer` method.
        :param kwargs: Keyword arguments to be passed to the DMA controller's
            `dma_transfer` method.
        :return: The result of the DMA transfer operation from the DMA controller,
            or None if no DMA controller is present.
        """
        if self.dma_controller:
            return self.dma_controller.dma_transfer(*args, **kwargs)
        return None

    def reset_all(self):
        """
        Resets all devices in the `resettable_devices` list.

        This method iterates through the `resettable_devices` attribute and invokes
        the `reset()` method for each device object in the list. It is intended to
        ensure that all devices in the list are reset to their initial state.

        :return: None
        """
        for dev in self.resettable_devices:
            dev.reset()

    def tick_all(self):
        """
        Iterates through all devices in the `tick_devices` list and invokes their `tick` method.

        This method is intended to allow each device in the list to execute its internal
        `tick` logic. It iterates through all instances contained in the `tick_devices`
        list and calls their respective `tick` method.

        :return: None
        :rtype: None
        """
        for dev in self.tick_devices:
            dev.tick()

    def clock_all(self, cycles: int):
        """
        Clock all devices in the `clocked_devices` list for a given number of cycles.

        This method iterates over all devices in the `clocked_devices` attribute and
        calls their `clock` method with the specified number of cycles.

        :param cycles: The number of cycles to clock for each device.
        :type cycles: int
        :return: None
        """
        for dev in self.clocked_devices:
            dev.clock(cycles)

    def print_device_map(self):
        """
        Prints the mapped I/O and MMIO devices.

        This method outputs two lists: one for the registered I/O devices and one for
        the registered MMIO devices. Each list provides a hexadecimal range for the
        device's address space and the class name of the device in the corresponding
        range. Devices and their ranges are displayed in sorted order based on their
        starting address.

        :return: None
        """
        print("🧩 Registered I/O Devices:")
        for start, end, dev in sorted(self.io_ranges):
            print(f"  0x{start:04X}-0x{end - 1:04X} → {dev.__class__.__name__}")

        print("📦 Registered MMIO Devices:")
        for start, end, dev in sorted(self.mmio_devices):
            print(f"  0x{start:08X}-0x{end - 1:08X} → {dev.__class__.__name__}")

    def get_io_device_for_port(self, port: int) -> Optional[IODevice]:
        """
        Finds and returns the IODevice instance for the specified port if it falls within
        any of the defined IO ranges. If no matching range is found, returns None.

        :param port: Port number to search for in the defined IO ranges.
        :type port: int
        :return: The IODevice object corresponding to the given port or None if no match
            is found.
        :rtype: Optional[IODevice]
        """
        for start, end, dev in self.io_ranges:
            if start <= port < end:
                return dev
        return None

    def get_mmio_device_for_address(self, addr: int) -> Optional[MMIODevice]:
        """
        Determine the corresponding MMIODevice for the given memory address.

        This method iterates through the list of memory-mapped I/O devices (MMIO)
        to identify the device associated with the provided memory address. Each
        device is defined by a start and end address range. If the address falls
        within one of these ranges, the corresponding MMIODevice instance is
        returned. If no matching device is found, the method returns None.

        :param addr: The memory address for which the corresponding MMIODevice
                     is to be determined.
        :type addr: int
        :return: The MMIODevice instance corresponding to the given memory
                 address, or None if no such device exists.
        :rtype: Optional[MMIODevice]
        """
        for start, end, dev in self.mmio_devices:
            if start <= addr < end:
                return dev
        return None
