from abc import ABC, abstractmethod
from typing import List, Union

PortRange = Union[int, tuple[int, int]]  # Either a single port or a (start, end) tuple

class IODevice(ABC):
    """
    Abstract base class for defining I/O device behavior in an emulator or system.

    This class provides an interface for implementing the handling of I/O operations
    and registering I/O port ranges that a specific device will respond to. Concrete
    implementations of this class are responsible for defining the behavior of I/O actions
    when devices interact with specific I/O ports.
    """

    @abstractmethod
    def on_io(self, port: int, size: int, value: int, is_write: bool):
        """
        Handles I/O operations by implementing an abstract method that reacts to
        specific port, size, and value information. Marks whether the operation
        is a write or read.

        :param port: The port number being accessed.
        :type port: int
        :param size: The size (in bytes) of the operation.
        :type size: int
        :param value: The data value relevant to the I/O operation.
        :type value: int
        :param is_write: A boolean indicating whether the operation is a write
            (True) or a read (False).
        :type is_write: bool
        :return: None
        :rtype: None
        """
        ...

    @abstractmethod
    def register_io_ports(self) -> List[PortRange]:
        """
        Defines an abstract method for registering input/output port ranges.

        This method serves as a contract that must be implemented by subclasses
        to specify the ranges of ports required for I/O operations. The method
        is expected to return a list of `PortRange` objects.

        :raises NotImplementedError: If not implemented in a subclass.
        :return: A list of `PortRange` objects representing the ranges of I/O ports
                 required by the implementing subclass.
        :rtype: List[PortRange]
        """
        ...
