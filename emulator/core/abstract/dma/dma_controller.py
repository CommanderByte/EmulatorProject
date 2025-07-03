import logging
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from emulator.core.abstract.dma.dma_device import DMADevice

logger = logging.getLogger(__name__)

class DMAController(ABC):
    """
    Abstract base class representing a Direct Memory Access (DMA) controller.

    Provides a blueprint for implementing DMA transfer operations. The controller
    is responsible for enabling direct data exchange between memory and devices
    while minimizing CPU involvement. It supports both read and write directions
    and can optionally manage multiple channels on legacy architectures.

    Its implementation must ensure synchronization and proper coordination of
    memory-to-device or device-to-memory operations.
    """

    @abstractmethod
    def dma_transfer(
        self,
        device: "DMADevice",
        addr: int,
        size: int,
        is_write: bool,
        channel: Optional[int] = None
    ):
        """
        Initiates a DMA (Direct Memory Access) transfer operation. This operation involves
        either reading data from the specified memory address to the device or writing
        data to the memory address from the device. The transfer can occur over an
        optional DMA channel, facilitating efficient data movement without involving
        the CPU.

        :param device: The DMA device instance responsible for managing the transfer.
        :type device: DMADevice
        :param addr: The memory address involved in the DMA transfer.
        :type addr: int
        :param size: The number of bytes to transfer.
        :type size: int
        :param is_write: A boolean indicating the direction of the transfer. If True,
                         the operation corresponds to writing to the memory address.
                         If False, it corresponds to reading from the memory address.
        :type is_write: bool
        :param channel: Specifies the DMA channel to use for the transfer, if any.
                        Defaults to None, implying automatic allocation or default
                        channel usage.
        :type channel: Optional[int]
        :return: None
        """
        ...
