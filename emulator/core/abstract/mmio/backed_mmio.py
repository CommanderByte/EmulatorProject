from abc import abstractmethod
from typing import List, Tuple

from emulator.core.abstract.mmio.mmio_device import MMIODevice


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