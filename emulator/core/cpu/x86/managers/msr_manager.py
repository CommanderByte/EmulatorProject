# emulator/core/cpu/x86/msr_manager.py
from dataclasses import dataclass, field
from typing import Dict, Union, Callable, Tuple
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDX
from emulator.core.cpu.x86.exceptions import ExceptionEvent

# Dynamic MSR callback types
MSRReadCallback  = Callable[[], int]
MSRWriteCallback = Callable[[int], None]

@dataclass
class MSRState:
    """
    Holds values and callbacks for MSR registers.
    """
    # Static MSR values: msr_index -> value
    msrs: Dict[int, int] = field(default_factory=dict)
    # Dynamic MSR callbacks: msr_index -> (read_cb, write_cb)
    callbacks: Dict[int, Tuple[MSRReadCallback, MSRWriteCallback]] = field(default_factory=dict)

class MSRManager(BaseManager):
    """
    Handles RDMSR and WRMSR instructions based on descriptor-defined msr_map.
    State block registered under 'msr'.
    """
    def __init__(self, cpu):
        super().__init__(cpu, block_name="msr")

    def create_state_block(self) -> MSRState:
        state = MSRState()
        # Populate from descriptor: msr_map may contain static ints or (rd_cb, wr_cb) tuples
        for msr, entry in self.cpu.capabilities.msr_map.items():
            if isinstance(entry, tuple) and len(entry) == 2 and callable(entry[0]):  # dynamic
                rd_cb, wr_cb = entry
                state.callbacks[msr] = (rd_cb, wr_cb)
            elif isinstance(entry, int):  # static default value
                state.msrs[msr] = entry
            else:
                raise ValueError(f"Invalid msr_map entry for MSR {msr}: {entry}")
        return state

    def register_events(self):
        # Subscribe to MSR read (RDMSR) and write (WRMSR)
        self.cpu.event_bus.subscribe(
            Event.MSR_READ, self.on_rdmsr, priority=100
        )
        self.cpu.event_bus.subscribe(
            Event.MSR_WRITE, self.on_wrmsr, priority=100
        )

    def on_rdmsr(self, ev) -> bool:
        uc  = ev.unicorn
        msr = ev.msr
        # Dynamic callback takes precedence
        if msr in self.state.callbacks:
            rd_cb, _ = self.state.callbacks[msr]
            value = rd_cb()
        else:
            if msr not in self.state.msrs:
                # unsupported MSR -> #GP
                raise ExceptionEvent(vector=13, error_code=0)
            value = self.state.msrs[msr]
        # Write to registers
        uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
        return True

    def on_wrmsr(self, ev) -> bool:
        uc  = ev.unicorn
        msr = ev.msr
        lo  = uc.reg_read(UC_X86_REG_RAX)
        hi  = uc.reg_read(UC_X86_REG_RDX)
        value = (hi << 32) | (lo & 0xFFFFFFFF)
        # Dynamic callback takes precedence
        if msr in self.state.callbacks:
            _, wr_cb = self.state.callbacks[msr]
            wr_cb(value)
        else:
            if msr not in self.state.msrs:
                # unsupported MSR -> #GP
                raise ExceptionEvent(vector=13, error_code=0)
            self.state.msrs[msr] = value
        return True
