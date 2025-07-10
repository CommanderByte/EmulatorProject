# emulator/core/cpu/x86/cr_manager.py
from emulator.core.cpu.x86.generic import GenericX86CPU
from emulator.core.event.x86.events import Event

class ControlRegisterManager:
    def __init__(self, cpu: GenericX86CPU):
        self.cpu   = cpu
        self.state = cpu.state
        bus = cpu.event_bus

        # subscribe to control-register events
        bus.subscribe(Event.CONTROL_REGISTER, self._on_mov_cr, priority=200)

    def _on_mov_cr(self, uc, insn):
        # operand[0] is CRn index, operand[1] is GPR
        cr_index = insn.operands[0].value
        value    = uc.reg_read(getattr(uc.const, f"X86_REG_CR{cr_index}"))

        # update your software state
        self.state.update_cr(cr_index, value)

        # if it’s CR0.PE, you might trigger mode-switch logic too
        # e.g. self.cpu.publish(Event.CPU_SYSENTER, …) or hand off to ModeSwitcher

        return True
