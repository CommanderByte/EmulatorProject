# emulator/core/cpu/x86/segment_manager.py
from dataclasses import dataclass
from capstone.x86 import X86_OP_MEM
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from emulator.core.cpu.x86.state import X86SegmentRegister

@dataclass
class SegmentState:
    cs: X86SegmentRegister
    ds: X86SegmentRegister
    es: X86SegmentRegister
    fs: X86SegmentRegister
    gs: X86SegmentRegister
    ss: X86SegmentRegister

class SegmentManager(BaseManager):
    def __init__(self, cpu):
        super().__init__(cpu, block_name="segment")

    def create_state_block(self) -> SegmentState:
        top = self.cpu.state
        return SegmentState(
            cs=top.cs, ds=top.ds, es=top.es,
            fs=top.fs, gs=top.gs, ss=top.ss
        )

    def register_events(self):
        bus = self.cpu.event_bus
        bus.subscribe(Event.CODE_INSN, self.on_code_insn, priority=300)

    def translate(self, seg: X86SegmentRegister, offset: int) -> int:
        if offset > seg.limit:
            from emulator.core.cpu.x86.exceptions import ExceptionEvent
            raise ExceptionEvent(vector=13, error_code=0)
        return seg.base + offset

    def on_code_insn(self, ev):
        uc   = ev.unicorn
        insn = ev.insn
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                disp = op.mem.disp
                lin  = self.translate(self.state.ds, disp)
                # validate or remap access here...
        return True
