# emulator/core/cpu/x86/manager_base.py
"""
Base classes for CPU managers and their associated state blocks.
Provides automatic registration into the central x86CPUState and a common event-subscription interface.
"""
from abc import ABC, abstractmethod

class BaseManager(ABC):
    """
    Abstract base for all x86 CPU subsystem managers.
    Managers inherit from this to reduce boilerplate: state registration and event setup.
    """
    def __init__(self, cpu, block_name: str):
        self.cpu = cpu
        # Create and register the state block
        self.state = self.create_state_block()
        cpu.state.register_block(block_name, self.state)
        # Subscribe to events
        self.register_events()

    @abstractmethod
    def create_state_block(self):
        """
        Return an object (e.g., dataclass or dict) representing this manager's state.
        """
        pass

    @abstractmethod
    def register_events(self):
        """
        Subscribe self methods to event_bus. Use cpu.event_bus.subscribe(...).
        """
        pass
