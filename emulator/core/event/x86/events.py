# emulator/core/cpu/x86/events.py

from enum import IntEnum, auto

class Event(IntEnum):
    # ─── Instruction Lifecycle ─────────────────────────────────────────────
    INSN_FETCH             = auto()  # before bytes are fetched
    INSN_DECODE            = auto()  # after bytes are fetched, before exec
    INSN_PREEXEC           = auto()  # right before Unicorn executes
    INSN_POSTEXEC          = auto()  # immediately after exec
    INSN_RETIRE            = auto()  # when instruction is fully retired

    # ─── CPU-specific Instructions ────────────────────────────────────────
    CPU_IN                 = auto()  # IN / INS
    CPU_OUT                = auto()  # OUT / OUTS
    CPU_SYSCALL            = auto()  # SYSCALL
    CPU_SYSENTER           = auto()  # SYSENTER
    CPU_CPUID              = auto()  # CPUID
    CPU_XGETBV             = auto()  # XGETBV
    CPU_XSETBV             = auto()  # XSETBV
    CPU_UNHOOKABLE         = auto()  # catch-all for unhookable ops

    # ─── Memory Access (linear vs physical) ───────────────────────────────
    MEM_READ_LINEAR        = auto()
    MEM_WRITE_LINEAR       = auto()
    MEM_READ_PHYSICAL      = auto()
    MEM_WRITE_PHYSICAL     = auto()
    MMIO_READ              = auto()
    MMIO_WRITE             = auto()

    # ─── I/O Ports & PCI ───────────────────────────────────────────────────
    IO_READ                = auto()  # same as PORT_READ
    IO_WRITE               = auto()  # same as PORT_WRITE
    PCI_CONFIG_READ        = auto()
    PCI_CONFIG_WRITE       = auto()

    # ─── Paging & Segmentation Faults ─────────────────────────────────────
    PAGE_FAULT             = auto()
    SEGMENT_FAULT          = auto()

    # ─── Descriptor/Table Operations ──────────────────────────────────────
    LGDT                   = auto()
    LIDT                   = auto()
    LLDT                   = auto()
    LMSW                   = auto()
    DESCRIPTOR_LOAD        = auto()  # alias for all of the above

    # ─── Control & Debug Registers ────────────────────────────────────────
    CR_READ                = auto()
    CR_WRITE               = auto()
    CONTROL_REGISTER       = CR_WRITE  # MOV CRx
    DR_READ                = auto()
    DR_WRITE               = auto()
    DEBUG_REGISTER         = DR_WRITE  # MOV DRx

    # ─── MSRs & Counters ───────────────────────────────────────────────────
    MSR_READ               = auto()  # RDMSR
    MSR_WRITE              = auto()  # WRMSR
    TSC_READ               = auto()  # RDTSC / RDTSCP
    PMC_READ               = auto()  # RDPMC

    # ─── Interrupts & Exceptions ──────────────────────────────────────────
    EXCEPTION              = auto()  # hardware-style faults
    SOFTWARE_INTERRUPT     = auto()  # INT n from code
    NMI                    = auto()  # non-maskable interrupt
    IRQ_RAISE              = auto()  # external IRQ
    IRQ_CLEAR              = auto()

    # ─── Mode, Reset, Lifecycle ───────────────────────────────────────────
    MODE_SWITCH            = auto()  # 16→32→64 transitions
    RESET                  = auto()  # CPU reset / INIT
