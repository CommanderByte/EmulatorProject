from abc import abstractmethod
from typing import Callable, Any, Optional, Tuple

from unicorn import Uc

from emulator.core.abstract.mmio.mmio_device import MMIODevice

UC_MMIO_READ_TYPE = Callable[[Uc, int, int, Any], int]
UC_MMIO_WRITE_TYPE = Callable[[Uc, int, int, int, Any], None]

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
