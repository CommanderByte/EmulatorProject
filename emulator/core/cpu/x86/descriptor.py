# emulator/core/cpu/x86/descriptor.py
from dataclasses import dataclass, field
from typing import List, Type, Dict, Union, Callable, Tuple

# Import all manager classes to be referenced here
from emulator.core.cpu.x86.managers import GDTManager, LDTManager, IDTManager, ExceptionManager
from managers.cr_manager import ControlRegisterManager
from managers.dr_manager import DebugRegisterManager
from managers.mode_switcher_manager import ModeSwitcherManager
from managers.msr_manager import MSRManager
from managers.cpuid_manager import CPUIDManager
from managers.segment_manager import SegmentManager

@dataclass
class CPUDescriptor:
    """
    Describes the static capabilities and manager composition for an x86 CPU variant.
    """
    # Human-readable identifier
    name: str

    # List of manager classes to instantiate and register on the event bus
    manager_classes: List[Type] = field(default_factory=lambda: [
        ControlRegisterManager,
        DebugRegisterManager,
        ModeSwitcherManager,
        GDTManager,
        LDTManager,
        SegmentManager,
        CPUIDManager,
        MSRManager,
        IDTManager,
        ExceptionManager,
        # …you can add PagingManager, IoPortManager, etc.
    ])

    # CPUID output mapping: leaf -> dict of {eax, ebx, ecx, edx}
    cpuid_leaves: Dict[int, Dict[str, int]] = field(default_factory=dict)

    # MSR map: MSR index -> either
    #   • an integer initial value, or
    #   • a (rd_callback, wr_callback) tuple for dynamic MSRs
    msr_map: Dict[int, Union[
        int,
        Tuple[Callable[[], int], Callable[[int], None]]
    ]] = field(default_factory=dict)

    # Default control register flags (e.g. CR0 initial value)
    default_cr0: int = 0x00000010  # real-mode by default

    # Default RFLAGS/EFLAGS value
    default_eflags: int = 0x00000002  # reserved bit

    # Optional CPU identification
    vendor_id: str = "Generic"
    family:    int = 0            # CPU family
    model:     int = 0            # CPU model
    stepping:  int = 0            # CPU stepping

    # You can also add other static config here, e.g.:
    # cache_line_size: int = 64
    # tsc_frequency_hz: int = 2_500_000_000