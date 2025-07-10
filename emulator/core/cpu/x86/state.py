# emulator/core/cpu/x86/state.py
from dataclasses import dataclass, field
from typing import Dict, Optional

@dataclass
class X86SegmentRegister:
    selector: int = 0
    base: int = 0
    limit: int = 0xFFFF
    flags: int = 0

@dataclass
class x86CPUState:
    """
    Maintains architectural state not fully modeled by Unicorn, including:
      - real / protected / long mode flags
      - control registers (CR0, CR4, etc.)
      - segment registers
      - instruction pointers for each mode
      - reset vectors for mode entry
    """
    # Mode flags
    protected_mode: bool = False
    long_mode: bool = False
    vm86_mode: bool = False

    # Control Registers
    cr: Dict[int, int] = field(default_factory=lambda: {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 8: 0})

    # Segment registers
    cs: X86SegmentRegister = field(default_factory=X86SegmentRegister)
    ds: X86SegmentRegister = field(default_factory=X86SegmentRegister)
    es: X86SegmentRegister = field(default_factory=X86SegmentRegister)
    fs: X86SegmentRegister = field(default_factory=X86SegmentRegister)
    gs: X86SegmentRegister = field(default_factory=X86SegmentRegister)
    ss: X86SegmentRegister = field(default_factory=X86SegmentRegister)

    # Instruction pointers
    ip: int = 0xFFF0      # real-mode offset
    eip: int = 0x0000     # protected-mode offset
    rip: int = 0x0000     # long-mode offset

    # Reset vectors
    reset_vector_real: int      = 0xFFFF0
    reset_vector_protected: int = 0x0000  # typically set by init code
    reset_vector_long: int      = 0x0000  # provided by loader

    def initialize_real_mode(self, uc, reset_vector: Optional[int] = None):
        """
        Enter real (16-bit) mode at the given physical reset vector.
        Computes CS:IP, zeroes other segments, and writes to Unicorn.
        """
        addr = reset_vector if reset_vector is not None else self.reset_vector_real
        seg = (addr >> 4) & 0xFFFF
        off = addr & 0xF
        self.protected_mode = False
        self.long_mode = False
        self.cs.selector = seg; self.cs.base = seg << 4
        self.ip = off
        # reset other segments
        for seg_reg in (self.ds, self.es, self.fs, self.gs, self.ss):
            seg_reg.selector = 0; seg_reg.base = 0
        # sync
        try:
            uc.reg_write(uc.const.X86_REG_CS, self.cs.selector)
            uc.reg_write(uc.const.X86_REG_IP, self.ip)
        except Exception:
            pass

    def initialize_protected_mode(self, uc, entry_point: Optional[int] = None, cs_selector: int = 0x8):
        """
        Enter protected (32-bit) mode at the given entry point and CS selector.
        Sets CR0.PE, updates flags, and writes CS:EIP into Unicorn.
        """
        # enable protected mode
        self.protected_mode = True
        self.cr[0] |= 0x1  # set PE
        # update mode flags
        self.update_cr(0, self.cr[0])
        # set CS:EIP
        sel = cs_selector & 0xFFFF
        self.cs.selector = sel; self.cs.base = sel << 4
        self.eip = entry_point if entry_point is not None else self.reset_vector_protected
        # reset other segments to flat defaults
        for seg_reg in (self.ds, self.es, self.fs, self.gs, self.ss):
            seg_reg.selector = sel; seg_reg.base = sel << 4
        # sync
        try:
            uc.reg_write(uc.const.X86_REG_CS, sel)
            uc.reg_write(uc.const.X86_REG_EIP, self.eip)
            # sync CR0
            uc.reg_write(uc.const.X86_REG_CR0, self.cr[0])
        except Exception:
            pass

    def initialize_long_mode(self, uc, entry_point: Optional[int] = None, cs_selector: int = 0x10):
        """
        Enter long (64-bit) mode at the given entry point and CS selector.
        Requires CR0.PE and CR4.PAE/LME, updates flags, and writes CS:RIP.
        """
        # enable protected + long mode
        self.protected_mode = True
        self.long_mode = True
        # set PE, PAE, LME bits
        self.cr[0] |= 0x1
        self.cr[4] |= (1 << 5) | (1 << 8)
        self.update_cr(0, self.cr[0]); self.update_cr(4, self.cr[4])
        # set CS:RIP
        sel = cs_selector & 0xFFFF
        self.cs.selector = sel; self.cs.base = sel << 4
        self.rip = entry_point if entry_point is not None else self.reset_vector_long
        # reset data segments
        for seg_reg in (self.ds, self.es, self.fs, self.gs, self.ss):
            seg_reg.selector = 0; seg_reg.base = 0
        # sync
        try:
            uc.reg_write(uc.const.X86_REG_CS, sel)
            uc.reg_write(uc.const.X86_REG_RIP, self.rip)
            uc.reg_write(uc.const.X86_REG_CR0, self.cr[0])
            uc.reg_write(uc.const.X86_REG_CR4, self.cr[4])
            # optionally write EFER.LME via MSR hook elsewhere
        except Exception:
            pass

    def update_cr(self, index: int, value: int):
        self.cr[index] = value
        if index == 0:
            self.protected_mode = bool(value & 0x1)
        elif index == 4:
            self.long_mode = bool(value & ((1 << 5) | (1 << 8)))

    def load_from_unicorn(self, uc):
        """
        Sync control registers and instruction pointers from Unicorn into state.
        """
        # CR regs
        for i in list(self.cr.keys()):
            try:
                self.cr[i] = uc.reg_read(getattr(uc.const, f"X86_REG_CR{i}"))
            except Exception:
                pass
        self.update_cr(0, self.cr.get(0, 0)); self.update_cr(4, self.cr.get(4, 0))
        # CS:IP/EIP/RIP
        try:
            self.cs.selector = uc.reg_read(uc.const.X86_REG_CS)
            if not self.protected_mode:
                self.ip = uc.reg_read(uc.const.X86_REG_IP)
                self.cs.base = self.cs.selector << 4
            elif self.long_mode:
                self.rip = uc.reg_read(uc.const.X86_REG_RIP)
            else:
                self.eip = uc.reg_read(uc.const.X86_REG_EIP)
        except Exception:
            pass

    def apply_to_unicorn(self, uc):
        """
        Write back control registers and instruction pointers from state into Unicorn.
        """
        for i, val in self.cr.items():
            try:
                uc.reg_write(getattr(uc.const, f"X86_REG_CR{i}"), val)
            except Exception:
                pass
        try:
            uc.reg_write(uc.const.X86_REG_CS, self.cs.selector)
            if not self.protected_mode:
                uc.reg_write(uc.const.X86_REG_IP, self.ip)
            elif self.long_mode:
                uc.reg_write(uc.const.X86_REG_RIP, self.rip)
            else:
                uc.reg_write(uc.const.X86_REG_EIP, self.eip)
        except Exception:
            pass
