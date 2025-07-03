from abc import ABC

class MemoryBackedDevice(ABC):
    """
    Mixin for devices with an internal memory array (RAM, ROM, buffers).
    """

    def get_memory(self) -> bytes:
        """
        Return a copy of internal memory.
        """
        raise NotImplementedError("This device does not expose memory")

    def set_memory(self, data: bytes):
        """
        Load memory content into the device.
        """
        raise NotImplementedError("This device does not accept memory updates")
