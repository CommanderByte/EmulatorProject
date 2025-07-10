"""
Unicorn hook helpers for x86-specific instructions and events.
Each module defines registration functions that wrap HookManager.add_hook.
"""
from .branch import BranchHook
from .cpuid import CpuidHook
from .cr import CrHook
from .debug import DebugHook
from .exception import ExceptionHook
from .int import InterruptHook
from .io import IoHook
from .msr import MsrHook
from .pci import PciHook
from .segment import SegmentHook
from .syscall import SyscallHook

__all__ = [
    "BranchHook",
    "CpuidHook",
    "CrHook",
    "DebugHook",
    "ExceptionHook",
    "InterruptHook",
    "IoHook",
    "MsrHook",
    "PciHook",
    "SegmentHook",
    "SyscallHook",
]