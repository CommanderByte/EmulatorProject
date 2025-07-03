import logging
from typing import List, Tuple, Any, Callable, Dict

from unicorn import Uc, UC_PROT_NONE

from emulator.core.abstract.devices.bus_participant import BusParticipant
from emulator.core.abstract.devices.device import Device
from emulator.core.abstract.devices.resettable_device import ResettableDevice
from emulator.core.abstract.devices.tick_device import TickDevice
from emulator.core.bus import Bus
from emulator.core.hooks import HookManager

logger = logging.getLogger(__name__)

DEFAULT_PERMISSIONS = UC_PROT_NONE

class Emulator:
    """
    Represents an emulator instance encapsulating the Unicorn engine, a bus system, and
    attached devices. This class serves as a central controller to manage hooks, memory
    mappings, and execution states of the emulator. It initializes necessary attributes
    and dependencies during creation.

    The emulator facilitates interaction with various simulated devices, memory regions,
    and hooks. It provides methods to manage devices, memory mappings, and device states,
    ensuring seamless operation of the emulated environment. This class is particularly
    suitable for use cases where modular hardware simulation and controlled execution
    are necessary.

    :ivar unicorn: Instance of the Unicorn engine initialized with the provided
        architecture and mode.
    :ivar hook_manager: Manages the hooks associated with the Unicorn engine
        during execution.
    :ivar bus: Main communication bus of the emulator to interact with attached devices.
    :ivar devices: List of connected peripherals or devices (instances of Device class).
    :ivar hooks: Collection of hooks registered, where each hook is represented as a
        dictionary containing its configuration and metadata.
    :ivar memory_map: Maps memory regions with their base address and size as a tuple.
    :ivar running: Boolean flag indicating the running state of the emulator.
    :type unicorn: Uc
    :type hook_manager: HookManager
    :type bus: Bus
    :type devices: List[Device]
    :type hooks: List[Dict[str, Any]]
    :type memory_map: Dict[int, Tuple[int, int]]
    :type running: bool
    """

    def __init__(self, architecture: int, mode: int):
        """
        Represents an emulator instance encapsulating the Unicorn engine, a bus system, and
        attached devices. This class serves as a central controller to manage hooks, memory
        mappings, and execution states of the emulator. It initializes necessary attributes
        and dependencies during creation.

        :param architecture: Specifies the architecture of the Unicorn engine to initialize.
        :param mode: Specifies the mode (e.g., endian type) for the Unicorn engine.

        :ivar unicorn: Instance of the Unicorn engine initialized with the provided
            architecture and mode.
        :ivar hook_manager: Manages the hooks associated with the Unicorn engine
            during execution.
        :ivar bus: Main communication bus of the emulator to interact with attached devices.
        :ivar devices: List of connected peripherals or devices (instances of Device class).
        :ivar hooks: Collection of hooks registered, where each hook is represented as a
            dictionary containing its configuration and metadata.
        :ivar memory_map: Maps memory regions with their base address and size as a tuple.
        :ivar running: Boolean flag indicating the running state of the emulator.
        """
        self.unicorn = Uc(architecture, mode)
        self.hook_manager = HookManager(self.unicorn)
        self.bus = Bus(self)
        self.devices: List[Device] = []
        self.hooks: List[Dict[str, Any]] = []
        self.memory_map: Dict[int, Tuple[int, int]] = {}
        self.running = False

    def add_device(self, device: Device):
        """
        Adds a device to the system by attaching it to the current instance,
        appending it to the list of managed devices, and connecting it to the bus.
        This method also ensures that the device is properly initialized and
        interfaced with the appropriate components of the system.

        :param device: The device to be added, which can be any instance of the Device
            class or its subclasses.
        :type device: Device
        :return: None
        """
        device.attach(self)
        self.devices.append(device)

        if isinstance(device, BusParticipant):
            device.on_bus_connect(self.bus)

        # Bus will handle IODevice, MMIODevice, etc.
        self.bus.attach_device(device)

    def detach_device(self, device: Device):
        """
        Detaches a device from the current system and removes it from the list of
        connected devices. If the device is a BusParticipant, it will trigger its
        on_bus_disconnect method prior to detachment. The device's detach method
        is also called as part of the clean-up process.

        :param device: The device to be detached from the system
        :type device: Device
        :return: None
        """
        if device in self.devices:
            if isinstance(device, BusParticipant):
                device.on_bus_disconnect()

            self.bus.detach_device(device)

            self.devices.remove(device)
            device.detach()

    def is_device_attached(self, device: Device) -> bool:
        """
        Checks if the given device is currently attached to the list of devices.

        This function determines whether the specified device instance exists in
        the collection of previously added devices. It helps in validating the
        attachment of a device before performing further operations related to it.

        :param device: The device instance to check if it is attached.
        :type device: Device
        :return: True if the device is attached, otherwise False.
        :rtype: bool
        """
        return device in self.devices

    def map_memory(self, address: int, region_size: int, permissions: int = DEFAULT_PERMISSIONS, content: bytes = b""):
        """
        Maps a memory region in the memory map with specified permissions and optionally
        initializes it with provided content. Ensures that the memory region at the given
        address is not already mapped before proceeding.

        :param address: The starting memory address where the region begins.
        :param region_size: The size of the memory region to be mapped.
        :param permissions: The access permissions for the memory region. Defaults to
            the value specified in DEFAULT_PERMISSIONS.
        :param content: The initial content to populate in the memory region, provided
            as a byte sequence. Defaults to an empty byte sequence.
        :return: None
        :raises ValueError: If the memory at the given address is already mapped.
        """
        if address in self.memory_map:
            raise ValueError(f"Memory at address {address:#x} is already mapped.")
        self._set_memory_map(address, region_size, permissions, content)
        self.memory_map[address] = (region_size, permissions)

    def _set_memory_map(self, address: int, region_size: int, permissions: int, content: bytes):
        """
        Sets the memory map with the specified parameters and content. The memory region is mapped
        at the given address with the defined size and permissions. Additionally, this writes provided
        content to the newly mapped memory region. If the memory mapping fails, an error will be logged.

        :param address: The starting address for the memory region.
        :param region_size: The size of the memory region to be mapped.
        :param permissions: The permissions for the memory region (e.g., read, write, execute).
        :param content: The content to be written to the newly mapped memory region.
        :return: None
        """
        if not isinstance(address, int) or not isinstance(region_size, int):
            raise TypeError("Address and region size must be integers.")
        if address < 0 or region_size <= 0:
            raise ValueError(f"Invalid address {address:#x} or region size {region_size}.")
        try:
            self.unicorn.mem_map(address, region_size, permissions)
        except Exception as e:
            logger.error(f"Memory mapping failed at {address:#x} with size {region_size}. Error: {e}")
        self._write_mem_content(address, content)

    def _write_mem_content(self, address: int, content: bytes):
        """
        Writes the provided content to the specified memory address within the unicorn emulator.

        :param address: The memory address where the content will be written.
        :param content: The data to write at the specified memory address.
        :return: None
        """
        if content:
            self.unicorn.mem_write(address, content)

    def add_hook(self, hook_type: int, callback: Callable):
        """
        Adds a new hook to the Unicorn instance and records it for tracking.

        Hooks are used to monitor or modify the execution of the code emulated
        by the Unicorn engine. This method enables the user to register a
        callback function associated with a specific hook type. The details of
        the hooks are stored in an internal list for reference.

        :param hook_type: The type of the hook to be added. It must correspond
            to one of the valid hook types supported by Unicorn.
        :param callback: A callable object that serves as the callback function
            executed when the hook is triggered. It should match the expected
            signature for the specified hook type.
        :return: None.
        """
        self.unicorn.hook_add(hook_type, callback)
        self.hooks.append({"type": hook_type, "callback": callback})

    def run(self, start_address: int, end_address: int, instruction_count: int = 0):
        """
        Runs the emulation process within the specified address range and execution count.

        This method starts the emulation using the Unicorn engine. The user can specify
        a starting and ending address, along with an optional instruction count, to control
        the emulation. The function sets the internal state to running and invokes Unicorn's
        `emu_start` method.

        :param start_address: The starting address for the emulation.
        :param end_address: The ending address for the emulation.
        :param instruction_count: Optional; the number of instructions to execute during
            the emulation. Defaults to 0, implying no limit.
        :return: None
        """
        self.running = True
        self.unicorn.emu_start(start_address, end_address, count=instruction_count)

    def reset(self):
        """
        Resets all resettable devices in the current collection.

        This method iterates through `self.devices` and checks if each device
        is an instance of `ResettableDevice`. If so, it calls the `reset`
        method on that device.

        :return: None
        """
        for device in self.devices:
            if isinstance(device, ResettableDevice):
                device.reset()

    def tick(self):
        """
        Iterates through a list of devices and calls the tick method on instances
        that are of type TickDevice. Each eligible device's tick method is called
        with an argument of 1.

        :param self: The instance of the class in which this method is defined.
        :type self:

        :raises AttributeError: If 'devices' attribute is not present in the class or
          if an item in 'devices' does not have the required interface for the 'tick'
          method.
        """
        for device in self.devices:
            if isinstance(device, TickDevice):
                device.tick(1)

    def clock(self, cycles: int = 1):
        """
        Performs clocking operation for all devices in the system.

        The method iterates through all devices and checks whether they
        have a callable method named 'clock'. If such a method exists for
        a device, it invokes the device's 'clock' method, passing the
        specified number of cycles as an argument.

        :param cycles: The number of clock cycles to execute for each
            device. Defaults to 1, if not provided.
        :type cycles: int
        :return: None
        """
        for device in self.devices:
            clock_method = getattr(device, "clock", None)
            if callable(clock_method):
                clock_method(cycles)
