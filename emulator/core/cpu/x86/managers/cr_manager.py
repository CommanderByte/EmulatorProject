# emulator/core/cpu/x86/cr_manager.py
from dataclasses import dataclass, field
from typing import Dict
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from unicorn.x86_const import (
    UC_X86_REG_CR0, UC_X86_REG_CR2, UC_X86_REG_CR3,
    UC_X86_REG_CR4, UC_X86_REG_CR8
)

@dataclass
class ControlRegisterState:
    # Tracks values for control registers CR0, CR2, CR3, CR4, CR8
    # Untracked registers default to 0
    cr: Dict[int, int] = field(default_factory=lambda: {
        0: 0, 2: 0, 3: 0, 4: 0, 8: 0
    })

class ControlRegisterManager(BaseManager):
    """
    Handles MOV to/from CRn instructions via the event bus.
    Updates control register state and triggers mode-switch logic when needed.
    """
    def __init__(self, cpu):
        # Register this manager's state block under 'control'
        super().__init__(cpu, block_name="control")

    def create_state_block(self) -> ControlRegisterState:
        # Initialize with CPU descriptor default CR0 if provided
        state = ControlRegisterState()
        default_cr0 = getattr(self.cpu.capabilities, 'default_cr0', 0)
        state.cr[0] = default_cr0
        return state

    def register_events(self):
        # Subscribe to control-register writes
        self.cpu.event_bus.subscribe(
            Event.CONTROL_REGISTER,
            self.on_mov_cr,
            priority=100
        )

    def on_mov_cr(self, ev) -> bool:
        uc   = ev.unicorn  # Unicorn instance
        insn = ev.insn     # Capstone instruction
        # CR index is first operand, GPR is second
        cr_index = insn.operands[0].value
        # Read value from the corresponding Unicorn register
        reg_const = {
            0: UC_X86_REG_CR0,
            2: UC_X86_REG_CR2,
            3: UC_X86_REG_CR3,
            4: UC_X86_REG_CR4,
            8: UC_X86_REG_CR8,
        }.get(cr_index)
        if reg_const is None:
            # Unsupported control register, ignore or raise
            return False
        value = uc.reg_read(reg_const)

        # Update state block
        self.state.cr[cr_index] = value

        # If CR0.PE changed, notify mode-switch logic
        if cr_index == 0:
            pe_bit_old = getattr(self.cpu.state, 'protected_mode', False)
            pe_bit_new = bool(value & 0x1)
            if pe_bit_new != pe_bit_old:
                # Update central mode flag
                self.cpu.state.protected_mode = pe_bit_new
                # Publish a MODE_SWITCH event for other managers
                self.cpu.event_bus.publish(Event.MODE_SWITCH, cr_index=0, new_value=value)

        return True
