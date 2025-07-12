# emulator/core/cpu/x86/generic.py
from emulator.core.cpu.base_cpu import CPU
from emulator.core.cpu.x86.state import x86CPUState
from emulator.core.cpu.x86.descriptor import CPUDescriptor
from emulator.core.event.x86 import Event


class GenericX86CPU(CPU):
    """
    A configurable x86 CPU: instantiates subsystem managers based on a descriptor.
    """
    def __init__(self, unicorn, hooks, event_bus=None, descriptor: CPUDescriptor=None):
        super().__init__(unicorn, hooks, event_bus)
        # CPU architectural state
        self.state = x86CPUState()
        # Use provided descriptor or default generic
        self.capabilities = descriptor or CPUDescriptor(name="x86-generic")
        # Instantiate & register all managers declared in descriptor
        for mgr_cls in self.capabilities.manager_classes:
            mgr = mgr_cls(self)
            # store under class name for easy access if needed
            setattr(self, mgr_cls.__name__.lower(), mgr)

    def setup_hooks(self):
        """
        Install unicorn hooks for code, memory, and ports. Subsystem managers
        will react via the event bus to these low-level events.
        """
        # existing hook setup logic...
        super().setup_hooks()

    def reset(self):
        """
        Reset CPU and bus to initial real-mode state and fire RESET event.
        """
        # Reset unicorn state
        self.unicorn.reset()
        # Initialize registers & segments for real-mode
        self.state.initialize_real_mode(self.unicorn)
        # Publish RESET so devices and managers can reinitialize
        self.event_bus.publish(Event.RESET)

    def run(self, start_addr=None, end_addr=None):
        """
        Begin execution at specified addresses (or defaults) under unicorn.
        """
        entry = start_addr or self.state.get_reset_vector()
        # call unicorn emu_start with mapped memory limits
        self.unicorn.emu_start(entry, end_addr or 0xFFFFFFFF)
