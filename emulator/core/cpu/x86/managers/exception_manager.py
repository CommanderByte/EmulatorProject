# emulator/core/cpu/x86/exception_manager.py

from dataclasses import dataclass
from unicorn import Uc
from unicorn.x86_const import (
    UC_X86_REG_CS, UC_X86_REG_EIP,
    UC_X86_REG_ESP, UC_X86_REG_SP
)
from emulator.core.cpu.x86.manager_base import BaseManager
from emulator.core.event.x86.events import Event
from emulator.core.cpu.x86.exceptions import ExceptionEvent

@dataclass
class ExceptionState:
    # could track last_vector, last_error, etc.
    pass

class ExceptionManager(BaseManager):
    """
    Centralizes exception delivery. On Event.EXCEPTION:
      1. Push FLAGS, CS, IP (and error code if present) to the stack
      2. Lookup vector in the IDTManager
      3. Far‐jump to the handler (update CS:IP)
    """
    def __init__(self, cpu):
        super().__init__(cpu, block_name="exception")

    def create_state_block(self) -> ExceptionState:
        return ExceptionState()

    def register_events(self):
        self.cpu.event_bus.subscribe(Event.EXCEPTION,
                                     self.on_exception,
                                     priority=500)

    def on_exception(self, ev) -> bool:
        uc: Uc = ev.unicorn
        vec = ev.vector
        err = ev.error_code

        # --- push context ---
        # read current CS:IP
        cs = uc.reg_read(UC_X86_REG_CS)
        ip = uc.reg_read(UC_X86_REG_EIP)
        # choose SP vs. ESP
        sp_reg = UC_X86_REG_SP if not self.cpu.state.protected_mode else UC_X86_REG_ESP
        sp = uc.reg_read(sp_reg)

        # push EFLAGS, CS, EIP
        # (real-mode: 16-bit pushes; protected: 32-bit)
        # NOTE: simplify to 32-bit for now:
        for value in (uc.reg_read(ev.unicorn.const.UC_X86_REG_RFLAGS), cs, ip):
            sp -= 4
            uc.reg_write(sp_reg, sp)
            uc.mem_write(sp, value.to_bytes(4, 'little'))

        # push error code if present (some vectors)
        if err is not None:
            sp -= 4
            uc.reg_write(sp_reg, sp)
            uc.mem_write(sp, err.to_bytes(4, 'little'))

        # --- lookup handler in IDT ---
        idt = self.cpu.state.get_block("idt")
        gate = idt.entries.get(vec)
        if gate is None:
            # No handler → double fault or triple fault
            raise ExceptionEvent(vector=8, error_code=0)

        # gate = (off_lo, sel, attrs, off_hi)
        off = (gate.offset_high << 16) | gate.offset_low
        sel = gate.selector

        # set new CS:IP
        uc.reg_write(UC_X86_REG_CS, sel)
        uc.reg_write(UC_X86_REG_EIP, off)

        # halt execution of the faulting instruction
        return False
