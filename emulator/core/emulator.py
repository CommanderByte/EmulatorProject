import logging
from typing import List, Tuple, Any

from unicorn import Uc, UC_PROT_NONE, UcError, UC_ERR_FETCH_UNMAPPED

# Core hook mixins
from emulator.core.hooks.base import HookMixin
from emulator.core.hooks.memory import MemoryHookMixin
from emulator.core.hooks.code import CodeHookMixin
from emulator.core.hooks.x86 import ExceptionHookMixin

# x86-specific hooks you care about:
from emulator.core.hooks.x86.pci import PCIHookMixin
from emulator.core.hooks.x86.segment import SegmentMixin
from emulator.core.hooks.x86.msr import MSRMixin
from emulator.core.hooks.x86.cpuid import CPUIDHookMixin
# … import any others you’ll use, e.g. IOPortHookMixin, ExceptionHookMixin, etc.

logger = logging.getLogger(__name__)

DEFAULT_PERMISSIONS = UC_PROT_NONE

class Emulator(PCIeHookMixin,
               SegmentMixin,
               MSRMixin,
               CPUIDHookMixin,
               ExceptionHookMixin,
               MemoryHookMixin,
               CodeHookMixin,
               HookMixin,
               ):
    """
    High‐level wrapper around Unicorn, using mixins instead of a monolithic Bus.
    Devices attach themselves by mapping memory or registering hooks via the mixins.
    """
    def __init__(self, arch: int, mode: int):
        # Instantiate Unicorn first
        self.uc = Uc(arch, mode)
        # Initialize all mixins with the Uc instance
        super().__init__(self.uc)

        self.devices: List[Any] = []
        self.memory_map: dict[int, Tuple[int,int]] = {}

    def add_device(self, device: Any):
        """
        Attach a Device to this Emulator. The Device.attach()
        method should set up any required memory maps or hooks.
        """
        device.attach(self)
        self.devices.append(device)
        logger.info(f"Device attached: {device.__class__.__name__}")

    def map_memory(self,
                   address: int,
                   size: int,
                   perms: int = DEFAULT_PERMISSIONS,
                   content: bytes = b""):
        """
        Map and (optionally) initialize a region of guest memory.
        """
        if address in self.memory_map:
            raise ValueError(f"0x{address:08X} already mapped")
        self.uc.mem_map(address, size, perms)
        if content:
            self.uc.mem_write(address, content)
        self.memory_map[address] = (size, perms)
        logger.debug(f"Mapped 0x{address:08X}-0x{address+size-1:08X}")

    def run(self, start: int, end: int, count: int = 0):
        try:
            self.uc.emu_start(start, end, count=count)
        except UcError as e:
            if e.errno == UC_ERR_FETCH_UNMAPPED:
                # 1) Print out all mapped regions
                print("=== Memory map ===")
                for base, (size, perms) in sorted(self.memory_map.items()):
                    print(f"  0x{base:08X} – 0x{base + size - 1:08X}\t size=0x{size:X}\t perms=0x{perms:X}")

                # 2) Find the highest‐addressed region
                max_base = max(self.memory_map)
                size, perms = self.memory_map[max_base]
                end_addr = max_base + size

                # 3) Read & print its last 16 bytes
                try:
                    tail = self.uc.mem_read(end_addr - 16, 16)
                    hexstr = " ".join(f"{b:02X}" for b in tail)
                    print(f"\nLast 16 bytes of 0x{max_base:08X}-0x{end_addr - 1:08X}:")
                    print(f"  {hexstr}")
                except UcError:
                    print(f"Could not read last 16 bytes at 0x{end_addr - 16:08X}")

            # re-raise so you still see the original traceback if you want
            raise

    def reset(self):
        """
        Call `reset()` on any device that defines it.
        """
        for dev in self.devices:
            reset_fn = getattr(dev, "reset", None)
            if callable(reset_fn):
                reset_fn()

    def tick(self):
        """
        Call `tick(1)` on any device that defines `tick()`
        """
        for dev in self.devices:
            tick_fn = getattr(dev, "tick", None)
            if callable(tick_fn):
                tick_fn(1)

    def clock(self, cycles: int = 1):
        """
        Call `clock(cycles)` on any clocked device.
        """
        for dev in self.devices:
            clk = getattr(dev, "clock", None)
            if callable(clk):
                clk(cycles)
