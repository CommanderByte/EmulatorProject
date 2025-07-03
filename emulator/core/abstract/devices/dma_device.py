from abc import ABC, abstractmethod
from typing import Optional
from threading import Lock
import logging

logger = logging.getLogger(__name__)

class DMADevice(ABC):
    """
    Represents an abstract base class for a DMA (Direct Memory Access) device.

    Provides abstract methods for handling DMA read and write operations, and an optional
    hook for handling completion of DMA transfers.

    :ivar _dma_lock: A lock object for synchronizing DMA access.
    :type _dma_lock: Lock
    """

    def __init__(self):
        """
        Class to manage a lock for Direct Memory Access (DMA) operations.

        This class initializes a lock object used to prevent multiple threads
        from accessing shared resources during DMA operations concurrently.
        Utilizing a lock ensures thread-safe behavior in any scenario requiring
        exclusive access during a critical operation.

        Attributes:
            _dma_lock (Lock): A threading lock object used for synchronization of
            DMA-related operations.
        """
        self._dma_lock = Lock()

    @abstractmethod
    def on_dma_read(self, addr: int, size: int) -> bytes:
        """
        Called when a DMA read operation is performed.

        This method is an abstraction for handling DMA read operations
        where the data at a specific memory address is accessed
        and returned as a byte array. It is expected to be overridden
        by any subclass implementing this abstract base class.

        :param addr: The memory address from which data should be read.
        :param size: The number of bytes to read from the specified address.
        :return: A bytes object containing the data read from the specified
            memory address.
        """
        ...

    @abstractmethod
    def on_dma_write(self, addr: int, data: bytes):
        """
        Handles write operations performed via Direct Memory Access (DMA). This abstract method must be
        implemented by subclasses to define specific behavior for handling DMA writes. It consumes the
        address and the data to be written.

        :param addr: The memory address where the data is to be written, represented as an integer.
        :param data: The bytes data to be written at the specified memory address.
        :return: None
        """
        ...

    def on_dma_complete(self, channel: Optional[int] = None):
        """
        Handles the completion of a DMA (Direct Memory Access) transfer. This function is typically
        invoked after the DMA controller finishes copying data from one memory region to another. The
        provided `channel` information, if any, specifies the DMA channel associated with the transfer.

        :param channel: The DMA channel number on which the operation was completed. Defaults to None
           if no specific channel is associated.
        :type channel: Optional[int]
        :return: None
        """
        logger.debug(f"📦 DMA transfer complete on {self.__class__.__name__}, channel={channel}")
