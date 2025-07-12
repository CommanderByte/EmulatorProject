# emulator/core/cpu/x86/ldt_manager.py
from dataclasses import dataclass
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from unicorn import Uc

@dataclass
class LDTState:
    selector: int = 0     # current LDTR selector
    base: int = 0
    limit: int = 0
    entries: dict = None

class LDTManager(BaseManager):
    def __init__(self, cpu):
        super().__init__(cpu, block_name="ldt")

    def create_state_block(self) -> LDTState:
        return LDTState(entries={})

    def register_events(self):
        bus = self.cpu.event_bus
        bus.subscribe(Event.DESCRIPTOR_LOAD, self.on_lldt, priority=150)

    def on_lldt(self, ev):
        uc   = ev.unicorn  # type: Uc
        insn = ev.insn
        # for LLDT, operand is a register or memory selector value
        selector = uc.reg_read(insn.operands[0].reg)
        self.state.selector = selector

        # Look up descriptor in GDT:
        gdt = self.cpu.state_blocks['gdt']
        entry = gdt.entries.get(selector)
        if not entry:
            from emulator.core.cpu.x86.exceptions import ExceptionEvent
            raise ExceptionEvent(vector=13, error_code=0)
        base, limit, flags = entry
        st = self.state
        st.base, st.limit = base, limit

        # parse LDT table entries similarly if needed
        return True
