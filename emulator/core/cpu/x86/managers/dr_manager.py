# emulator/core/cpu/x86/dr_manager.py
from dataclasses import dataclass, field
from typing import Dict
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from unicorn.x86_const import (
    UC_X86_REG_DR0, UC_X86_REG_DR1, UC_X86_REG_DR2, UC_X86_REG_DR3,
    UC_X86_REG_DR6, UC_X86_REG_DR7
)

@dataclass
class DebugRegisterState:
    """
    Holds the values of debug registers DR0-DR7 (where supported).
    """
    dr: Dict[int, int] = field(default_factory=lambda: {
        0: 0, 1: 0, 2: 0, 3: 0, 6: 0, 7: 0
    })

class DebugRegisterManager(BaseManager):
    """
    Handles MOV to/from debug registers via the event bus.
    Updates debug register state accordingly.
    """
    def __init__(self, cpu):
        # Register this manager's state block under 'debug'
        super().__init__(cpu, block_name="debug")

    def create_state_block(self) -> DebugRegisterState:
        # Initialize with default zeros for all debug regs
        return DebugRegisterState()

    def register_events(self):
        # Subscribe to debug-register write events
        self.cpu.event_bus.subscribe(
            Event.DEBUG_REGISTER,
            self.on_mov_dr,
            priority=100
        )

    def on_mov_dr(self, ev) -> bool:
        uc   = ev.unicorn  # Unicorn instance
        insn = ev.insn     # Capstone instruction
        # First operand is the debug register index (Capstone reg enum)
        op0 = insn.operands[0]
        if op0.type != op0.REG:
            return True
        cap_reg = op0.reg
        # Map Capstone reg IDs to our DR index (0-3,6,7)
        cap_to_index = {
            UC_X86_REG_DR0: 0,
            UC_X86_REG_DR1: 1,
            UC_X86_REG_DR2: 2,
            UC_X86_REG_DR3: 3,
            UC_X86_REG_DR6: 6,
            UC_X86_REG_DR7: 7,
        }
        cr_index = cap_to_index.get(cap_reg)
        if cr_index is None:
            return True
        # Read value from Unicorn
        unicorn_const = cap_reg
        value = uc.reg_read(unicorn_const)
        # Update state block
        self.state.dr[cr_index] = value
        return True
