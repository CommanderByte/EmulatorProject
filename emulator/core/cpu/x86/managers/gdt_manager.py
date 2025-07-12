# emulator/core/cpu/x86/gdt_manager.py
from dataclasses import dataclass
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from unicorn import Uc

@dataclass
class GDTState:
    base: int = 0
    limit: int = 0
    # Optionally: parsed entries mapping selector→(base,limit,flags)
    entries: dict = None

class GDTManager(BaseManager):
    def __init__(self, cpu):
        super().__init__(cpu, block_name="gdt")

    def create_state_block(self) -> GDTState:
        return GDTState(entries={})

    def register_events(self):
        bus = self.cpu.event_bus
        bus.subscribe(Event.DESCRIPTOR_LOAD, self.on_lgdt, priority=150)

    def on_lgdt(self, ev):
        uc   = ev.unicorn  # type: Uc
        insn = ev.insn
        # assume first operand is [addr]
        addr = insn.operands[0].mem.disp
        # GDT descriptor is 6 bytes: limit(2), base(4)
        data = uc.mem_read(addr, 6)
        limit = int.from_bytes(data[0:2], 'little')
        base  = int.from_bytes(data[2:6], 'little')
        st    = self.state
        st.base, st.limit = base, limit

        # Optionally parse all descriptors into st.entries:
        num = (limit + 1) // 8
        for i in range(num):
            desc = uc.mem_read(base + i*8, 8)
            # parse desc → selector=i*8 → (b,l,flags)
            # st.entries[i*8] = parsed_tuple

        return True
