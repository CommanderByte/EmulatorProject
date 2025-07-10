# emulator/core/cpu/x86/dr_manager.py
from capstone.x86_const import (
    X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3,
    X86_REG_DR6, X86_REG_DR7
)
from emulator.core.cpu.x86.generic import GenericX86CPU
from emulator.core.event.x86.events import Event

class DebugRegisterManager:
    """
    Manager for MOV to/from debug registers (DR0-DR7).
    Subscribes to Event.DEBUG_REGISTER and updates CPU state accordingly.
    """
    def __init__(self, cpu: GenericX86CPU):
        self.cpu   = cpu
        self.state = cpu.state
        bus = cpu.event_bus

        # subscribe to debug-register events
        bus.subscribe(Event.DEBUG_REGISTER, self._on_mov_dr, priority=200)

    def _on_mov_dr(self, uc, insn):
        # Determine which debug register, DRn, is accessed
        # operand[0] is DRn, operand[1] is general-purpose register
        op0 = insn.operands[0]
        if op0.type != op0.REG:
            return True
        dr_index = op0.reg  # capstone register ID
        # Map capstone REG_DRn to unicorn X86_REG_DRn constant
        # Construct attribute name, e.g. 'X86_REG_DR0', etc.
        # Dr indices: DR0..DR3, DR6, DR7
        dr_map = {
            123: X86_REG_DR0,  # capstone.op_reg constants vary, adjust if needed
            124: X86_REG_DR1,
            125: X86_REG_DR2,
            126: X86_REG_DR3,
            130: X86_REG_DR6,
            131: X86_REG_DR7,
        }
        unicorn_dr = dr_map.get(dr_index)
        if unicorn_dr is None:
            return True
        # Read the value from the debug register
        value = uc.reg_read(uc.const.__getattribute__(uc.const, f"X86_REG_DR{dr_index - 123}"))
        # Update software state (add a dict or attribute for DR regs)
        # Assuming state.cr also holds dr, or extend state as needed
        self.state.cr.update({dr_index - 123: value})
        return True