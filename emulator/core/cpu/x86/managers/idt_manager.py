# emulator/core/cpu/x86/idt_manager.py

from dataclasses import dataclass
from unicorn import Uc
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event

@dataclass
class IDTState:
    base: int = 0
    limit: int = 0
    # selector → (offset_low, selector, type_attr, offset_high)
    entries: dict = None

class IDTManager(BaseManager):
    """
    Loads the Interrupt Descriptor Table via LIDT
    and provides a lookup for interrupt/exception vectors.
    """
    def __init__(self, cpu):
        super().__init__(cpu, block_name="idt")

    def create_state_block(self) -> IDTState:
        # initialize entries mapping
        return IDTState(entries={})

    def register_events(self):
        bus = self.cpu.event_bus
        # LIDT publishes DESCRIPTOR_LOAD
        bus.subscribe(Event.DESCRIPTOR_LOAD, self.on_lidt, priority=150)

    def on_lidt(self, ev) -> bool:
        uc: Uc = ev.unicorn
        insn = ev.insn
        # assume operand[0] is mem:[addr]
        addr = insn.operands[0].mem.disp
        # IDT descriptor is 6 bytes in 16/32-bit modes (limit:2, base:4),
        # or 10 bytes in 64-bit (limit:2, base:8). For now read 6:
        data = uc.mem_read(addr, 6)
        limit = int.from_bytes(data[0:2], 'little')
        base  = int.from_bytes(data[2:6], 'little')
        st    = self.state
        st.base, st.limit = base, limit

        # Optionally parse all gates into st.entries:
        # count = (limit+1)//8
        # for vec in range(count):
        #     desc = uc.mem_read(base + vec*8, 8)
        #     # parse desc → (off_lo, sel, attrs, off_hi)
        #     st.entries[vec] = parsed_tuple

        return True
