# emulator/core/events.py
from enum import IntEnum, auto

class Event(IntEnum):
    # CPU instruction events

    CPU_IN            = auto()
    CPU_OUT           = auto()
    CPU_SYSCALL       = auto()
    CPU_SYSENTER      = auto()
    CPU_CPUID         = auto()
    CPU_UNHOOKABLE    = auto()

    # Bus/Memory events
    IO_READ           = auto()
    IO_WRITE          = auto()
    MMIO_READ         = auto()
    MMIO_WRITE        = auto()
    IRQ_RAISE         = auto()
    IRQ_CLEAR         = auto()
    PCI_CONFIG_READ   = auto()
    PCI_CONFIG_WRITE  = auto()

    # Fallback code hook event
    CODE_INSN         = auto()  # generic catch-all for unhooked instructions


    # Descriptor and system events
    DESCRIPTOR_LOAD   = auto()  # LGDT, LIDT, LLDT, LMSW, etc.
    TSC_READ          = auto()  # RDTSC, RDTSCP
    PMC_READ          = auto()  # RDPMC
    CONTROL_REGISTER  = auto()  # MOV CRx
    DEBUG_REGISTER    = auto()  # MOV DRx
    MODE_SWITCH       = auto()  # Switch between 16/32/64 bit modes