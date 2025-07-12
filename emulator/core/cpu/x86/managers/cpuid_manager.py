# emulator/core/cpu/x86/cpuid_manager.py
from dataclasses import dataclass, field
from typing import Dict, Union, Callable
from emulator.core.cpu.x86.base_manager import BaseManager
from emulator.core.event.x86.events import Event
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX,
    UC_X86_REG_ECX, UC_X86_REG_EDX
)

# Define the per-manager state block
@dataclass
class CPUIDState:
    # Map leaf -> either a simple register dict or a callable for dynamic leaves
    leaves: Dict[int, Union[
        Dict[str, int],
        Callable[[int, int], Dict[str, int]]
    ]] = field(default_factory=dict)

class CPUIDManager(BaseManager):
    """
    Handles the CPUID instruction by responding with values from the CPUIDState.
    """
    def __init__(self, cpu):
        # Register state block under "cpuid"
        super().__init__(cpu, block_name="cpuid")

    def create_state_block(self) -> CPUIDState:
        # Copy descriptor leaves into the state block for isolation
        desc_leaves = self.cpu.capabilities.cpuid_leaves
        # Make a shallow copy of the mapping (deep copy if needed for nested dicts)
        return CPUIDState(leaves=dict(desc_leaves))

    def register_events(self):
        # Subscribe to CPUID events from the emulator
        self.cpu.event_bus.subscribe(
            Event.CPU_CPUID,
            self.on_cpuid,
            priority=100
        )

    def on_cpuid(self, ev) -> bool:
        uc = ev.unicorn  # the Unicorn instance
        # Read input leaf (EAX) and subleaf (ECX)
        leaf = uc.reg_read(UC_X86_REG_EAX)
        subleaf = uc.reg_read(UC_X86_REG_ECX)
        entry = self.state.leaves.get(leaf)
        # Determine output tuple
        if callable(entry):
            out = entry(leaf, subleaf)
        elif isinstance(entry, dict):
            # Handle possible subleaf dicts: {subleaf: regs}
            if subleaf in entry and isinstance(entry[subleaf], dict):
                out = entry[subleaf]
            else:
                out = entry
        else:
            out = {'eax': 0, 'ebx': 0, 'ecx': 0, 'edx': 0}
        # Write registers
        uc.reg_write(UC_X86_REG_EAX, out.get('eax', 0))
        uc.reg_write(UC_X86_REG_EBX, out.get('ebx', 0))
        uc.reg_write(UC_X86_REG_ECX, out.get('ecx', 0))
        uc.reg_write(UC_X86_REG_EDX, out.get('edx', 0))
        return True
