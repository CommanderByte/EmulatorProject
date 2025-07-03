from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Callable, Any, Tuple
from unicorn import Uc

UC_MMIO_READ_TYPE = Callable[[Uc, int, int, Any], int]
UC_MMIO_WRITE_TYPE = Callable[[Uc, int, int, int, Any], None]


@dataclass(frozen=True)
class MMIORange:
    """
    Represents a memory-mapped I/O (MMIO) range.

    This class is used to define a range in a memory-mapped I/O system with a
    specific start address and length. Instances are immutable due to the
    dataclass being frozen.

    :ivar start: Starting address of the MMIO range.
    :type start: int
    :ivar length: Length of the MMIO range in bytes.
    :type length: int
    """

    start: int
    length: int

    def end(self) -> int:
        """
        Calculate and return the ending index by adding the starting index and the length.

        :return: The ending index as an integer.
        :rtype: int
        """
        return self.start + self.length


class MMIODevice(ABC):
    """
    Represents an abstract base class for memory-mapped I/O (MMIO) devices.

    This class serves as a blueprint for defining MMIO devices. It enforces the
    implementation of methods for registering MMIO ranges that are critical for
    device functionality. Subclasses inheriting from this class must provide
    their own implementations for the abstract methods.

    :ivar mmio_ranges: A list of memory-mapped I/O ranges that belong to the device.
    :type mmio_ranges: List[MMIORange]
    """

    @abstractmethod
    def register_mmio_ranges(self) -> List[MMIORange]:
        """
        Abstract method to register Memory-Mapped I/O (MMIO) address ranges required by
        a specific implementation. This method must be implemented in a subclass to
        define the MMIO regions needed for an operation or device initialization.

        This process is essential for providing the necessary address ranges that
        enable communication between the application and hardware components.

        :raises NotImplementedError: If the subclass does not provide an implementation.

        :return: A list of `MMIORange` instances that describe the MMIO regions.
        :rtype: List[MMIORange]
        """
        pass


class CallbackMMIODevice(MMIODevice):
    """
    CallbackMMIODevice serves as a base class for handling memory-mapped I/O (MMIO) operations with
    callbacks. It defines the structure and mechanism for registering read and write callback functions
    used to respond to MMIO read and write accesses. This class is expected to be extended to implement
    specific behaviors for on_mmio calls.

    :ivar _read_callback: Internal read callback function to handle MMIO read operations.
    :type _read_callback: Callable[[Uc, int, int, Any], int]
    :ivar _write_callback: Internal write callback function to handle MMIO write operations.
    :type _write_callback: Callable[[Uc, int, int, int, Any], None]
    """

    @abstractmethod
    def on_mmio(self, address: int, size: int, value: int, is_write: bool):
        """
        Handles memory-mapped I/O (MMIO) operations by providing an abstract method
        to process read or write requests. This method is intended to be overridden
        by subclasses, enabling user-defined handling of specific MMIO transactions.
        The method is invoked when an MMIO operation occurs with the specified
        parameters. Subclasses must implement the functionality to handle or process
        the requests based on the provided details.

        :param address: The memory address involved in the MMIO operation.
        :type address: int
        :param size: The size of the operation, typically specified in bytes.
        :type size: int
        :param value: The value to be written or read during the MMIO access.
        :type value: int
        :param is_write: Flag indicating whether the operation is a write
                         (True) or a read (False).
        :type is_write: bool
        :return: None
        """
        pass

    def get_mmio_callbacks(self) -> Tuple[
        Optional[UC_MMIO_READ_TYPE], Any,
        Optional[UC_MMIO_WRITE_TYPE], Any
    ]:
        """
        Retrieve memory-mapped I/O (MMIO) read and write callbacks.

        This method provides access to the registered MMIO read and write
        callbacks, if any, for the corresponding event handling. It is typically
        used to interact with external components for memory operations or device
        emulation. The method also returns additional positional arguments, which
        are currently set to None.

        :return: A tuple containing optional read callback, associated read
            arguments, optional write callback, and associated write arguments.
        :rtype: Tuple[Optional[UC_MMIO_READ_TYPE], Any, Optional[UC_MMIO_WRITE_TYPE], Any]
        """
        return (
            self._read_callback,
            None,
            self._write_callback,
            None
        )

    def _read_callback(self, uc: Uc, address: int, size: int, user_data: Any) -> int:
        """
        Represents a callback function invoked during memory-mapped I/O operations
        to handle read operations in a Unicorn emulation context.

        :param uc: The Unicorn instance where the callback is registered.
        :type uc: Uc
        :param address: The memory address to read data from during the operation.
        :type address: int
        :param size: The size of the data to read, in bytes.
        :type size: int
        :param user_data: Additional user-provided data passed to the callback function.
        :type user_data: Any
        :return: The data read from the specified address.
        :rtype: int
        """
        return self.on_mmio(address, size, 0, False)

    def _write_callback(self, uc: Uc, address: int, size: int, value: int, user_data: Any) -> None:
        """
        Handles the memory write operation callback.

        This method is triggered during the memory write operations within the MMIO
        (memory-mapped input/output) system. It processes the relevant parameters such
        as the memory address, size of data being written, and the value that is
        written, and invokes the handler method `on_mmio`.

        :param uc: An instance of the Unicorn emulator that acts as a context for the
            callback.
        :param address: The memory address where the write operation occurs.
        :param size: The size, in bytes, of the data being written.
        :param value: The value being written to the memory address.
        :param user_data: Additional user-defined data passed to the callback.
        :return: This method returns nothing.
        """
        self.on_mmio(address, size, value, True)


class BackedMMIODevice(MMIODevice):
    """
    Provides an abstract base class for memory-mapped I/O devices
    that support backing memory regions. This class outlines an
    interface for retrieving memory regions that must be implemented
    by subclasses.

    This is designed to assist in managing and interacting with
    hardware or virtual devices backed by specific memory regions.

    Subclasses are required to define the behavior for retrieving
    a list of memory regions by implementing the `get_backed_memory`
    method.

    :ivar device_name: Name of the device associated with this I/O region.
    :type device_name: str
    :ivar base_address: The base address of this memory-mapped device.
    :type base_address: int
    :ivar region_size: The size of the memory region mapped for the device.
    :type region_size: int
    """

    @abstractmethod
    def get_backed_memory(self) -> List[Tuple[int, bytes]]:
        """
        Abstract method to get a list of backed memory segments.

        This method must be implemented by subclasses to provide a list of backed memory
        segments. Each memory segment is represented as a tuple containing an integer and
        a bytes object. The integer represents the address or offset, and the bytes object
        contains the corresponding data in memory at that address.

        The method is designed to be used in scenarios where memory segments are backed by
        data, such as within certain virtualization or memory mapping contexts.

        :raises NotImplementedError: If the method is not implemented by a subclass.

        :return: A list of tuples where each tuple consists of an integer and a bytes object.
        :rtype: List[Tuple[int, bytes]]
        """
        pass
