# emulator/core/cpu/x86/mode_switcher.py

from capstone.x86_const import X86_INS_LJMP
from unicorn import Uc
from unicorn.unicorn_const import UC_MODE_32, UC_MODE_64, UC_ARCH_X86

from emulator.core.event.x86.events import Event
from emulator.core.cpu.x86.generic import GenericX86CPU

class ModeSwitcher:
    """
    Detects and orchestrates x86 mode switches (16→32, 32→64).

    Listens for MOV to CR0/CR4 and far JMP (LJMP) events, then
    tears down and reinitializes the Unicorn engine in the new mode.
    """
    def __init__(self, cpu: GenericX86CPU):
        self.cpu = cpu
        self.state = cpu.state
        self.bus = cpu.event_bus
        self._saw_pe = False
        self._saw_lme = False

        # Watch for writes to CR0 (PE bit) and CR4 (LME bit)
        self.bus.subscribe(Event.CONTROL_REGISTER, self._on_mov_cr, priority=200)
        # Watch for far jumps (LJMP) to complete the switch
        self.bus.subscribe(Event.CODE_INSN,        self._on_insn,    priority=100)

    def _on_mov_cr(self, uc: Uc, insn) -> bool:
        # operand[0] is CR index
        idx = insn.operands[0].reg - insn.reg_list[0]  # deduce CRn
        new_val = uc.reg_read(getattr(uc.const, f"X86_REG_CR{idx}"))
        if idx == 0 and (new_val & 1):
            self._saw_pe = True
        if idx == 4 and (new_val & ((1<<5)|(1<<8))):
            self._saw_lme = True
        return True

    def _on_insn(self, uc: Uc, insn) -> bool:
        # Only act if we’ve already set mode bits
        if not self._saw_pe and not self._saw_lme:
            return True
        # Detect far-jump opcode (LJMP)
        if insn.id == X86_INS_LJMP:
            # Trigger the mode switch sequence
            self._switch_mode(uc)
            return False  # halt current emulation run
        return True

    def _switch_mode(self, uc: Uc):
        # 1) Snapshot state and memory
        self.state.load_from_unicorn(uc)
        mem_snapshot = self.cpu.memory.snapshot_all()

        # 2) Determine new mode
        if self._saw_lme:
            new_mode = UC_MODE_64
        elif self._saw_pe:
            new_mode = UC_MODE_32
        else:
            # fallback: remain in 16-bit
            new_mode = None

        # 3) Teardown & recreate
        uc.emu_stop()
        new_uc = Uc(UC_ARCH_X86, new_mode)
        new_hooks = self.cpu.hooks.__class__(new_uc)
        self.cpu.uc = new_uc
        self.cpu.hooks = new_hooks

        # 4) Restore memory & state
        self.cpu.memory.restore(mem_snapshot, new_uc)
        if new_mode == UC_MODE_32:
            self.state.initialize_protected_mode(new_uc)
        elif new_mode == UC_MODE_64:
            self.state.initialize_long_mode(new_uc)
        else:
            self.state.initialize_real_mode(new_uc)
        self.state.apply_to_unicorn(new_uc)

        # 5) Reinstall hooks
        self.cpu.setup_hooks()

        # 6) Reset switch flags
        self._saw_pe = False
        self._saw_lme = False

        # after hooks are reinstalled and state applied
        self.bus.publish(Event.MODE_SWITCH,
                         old_mode=old_mode,
                         new_mode=new_mode,
                         entry_point=self.state.eip if new_mode == UC_MODE_32 else self.state.rip)
