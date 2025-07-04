"""Top-level package for the emulator examples."""

from .core import Emulator, Bus, HookManager
from .platforms.bios_x86 import setup_bios_x86

__all__ = [
    "Emulator",
    "Bus",
    "HookManager",
    "setup_bios_x86",
]

