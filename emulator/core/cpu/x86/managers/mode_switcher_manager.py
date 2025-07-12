# emulator/core/cpu/x86/mode_switcher_manager.py
from dataclasses import dataclass, field
from typing import Optional
from unicorn import Uc
from unicorn.unicorn_const import UC_MODE_32, UC_MODE_64, UC_ARCH_X86
from capstone.x86_const import X86_INS_LJMP

from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from emulator.core.cpu.x86.state import x86CPUState
from emulator.core.cpu.memory import MemoryManager  # hypothetical memory snapshot/restore

@dataclass
class ModeSwitcherState:
    """
    Tracks pending mode-switch flags for Protection Enable (PE) and Long Mode Enable (LME).
    """
    saw_pe: bool = False
    saw_lme: bool = False
    old_mode: Optional[int] = None

class ModeSwitcherManager(BaseManager):
    """
    Detects and orchestrates x86 mode switches (16→32, 32→64).
    Listens for writes to CR0/CR4 and far JMP (LJMP) events, then tears down and reinitializes the Unicorn engine in the new mode.
    """
    def __init__(self, cpu):
        # Register this manager's state block under 'mode_switcher'
        super().__init__(cpu, block_name="mode_switcher")
        self.cpu = cpu
        self.bus = cpu.event_bus

    def create_state_block(self) -> ModeSwitcherState:
        return ModeSwitcherState()

    def register_events(self):
        # Watch for control register writes (CR0 & CR4)
        self.cpu.event_bus.subscribe(
            Event.CONTROL_REGISTER,
            self.on_mov_cr,
            priority=200
        )
        # Watch for far JMP instructions to trigger switch
        self.cpu.event_bus.subscribe(
            Event.CODE_INSN,
            self.on_code_insn,
            priority=150
        )

    def on_mov_cr(self, ev) -> bool:
        uc   = ev.unicorn
        insn = ev.insn
        # Determine CR index from first operand
        idx = insn.operands[0].value
        val = uc.reg_read(getattr(uc.const, f"X86_REG_CR{idx}"))
        # Track Protection Enable (bit 0 of CR0)
        if idx == 0 and (val & 0x1):
            self.state.saw_pe = True
            # record old mode for event
            self.state.old_mode = UC_ARCH_X86 | (UC_MODE_64 if self.cpu.state.long_mode else UC_MODE_32 if self.cpu.state.protected_mode else 0)
        # Track Long Mode Enable bits in CR4 (LME is bit 8)
        if idx == 4 and (val & (1 << 8)):
            self.state.saw_lme = True
        return True

    def on_code_insn(self, ev) -> bool:
        # Only act after seeing a mode bit write
        if not (self.state.saw_pe or self.state.saw_lme):
            return True
        insn = ev.insn
        # Detect far-jump opcode (LJMP)
        if insn.id == X86_INS_LJMP:
            self._perform_switch(ev.unicorn)
            # halt current emulation so reset is clean
            return False
        return True

    def _perform_switch(self, uc: Uc):
        # 1) Snapshot CPU state and memory
        state_snapshot = self.cpu.state.snapshot()
        mem_snapshot   = self.cpu.memory.snapshot_all()

        # 2) Determine new mode
        new_mode = None
        if self.state.saw_lme:
            new_mode = UC_MODE_64
        elif self.state.saw_pe:
            new_mode = UC_MODE_32

        # 3) Re-instantiate Unicorn with new mode
        uc.emu_stop()
        old_mode = self.state.old_mode
        new_uc = Uc(UC_ARCH_X86, new_mode)
        # replace engine and hooks
        self.cpu.unicorn = new_uc
        self.cpu.hooks = self.cpu.hooks.__class__(new_uc)

        # 4) Restore memory and state
        self.cpu.memory.restore(mem_snapshot, new_uc)
        # reinitialize core state by delegating to x86CPUState
        if new_mode == UC_MODE_64:
            self.cpu.state.long_mode = True
        elif new_mode == UC_MODE_32:
            self.cpu.state.protected_mode = True
        else:
            # fallback to real mode
            self.cpu.state.protected_mode = False
            self.cpu.state.long_mode = False
        # restore per-block state
        self.cpu.state.restore(state_snapshot)
        # apply register state back into unicorn
        self.cpu.state.apply_to_unicorn(new_uc)

        # 5) Reinstall hooks for the new engine
        self.cpu.setup_hooks()

        # 6) Fire MODE_SWITCH event
        self.cpu.event_bus.publish(
            Event.MODE_SWITCH,
            old_mode=old_mode,
            new_mode=new_mode
        )
        # reset local flags
        self.state.saw_pe = False
        self.state.saw_lme = False

# Note: Ensure GenericX86CPU.setup_hooks() installs Event.CODE_INSN and CONTROL_REGISTER hooks correctly.
