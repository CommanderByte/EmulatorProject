# emulator/core/cpu/base_cpu.py
import abc
from typing import Optional, Any, Callable, List

from unicorn import Uc
from capstone import Cs

from emulator.core.hooks import HookManager
from emulator.core.event.event_bus import EventBus

class CPU(abc.ABC):
    """
    Abstract CPU class: holds a Unicorn instance, a shared HookManager, and an EventBus.
    Also provides a Capstone disassembler configured by bit_mode.
    """
    def __init__(
        self,
        unicorn: Uc,
        hooks: HookManager,
        event_bus: Optional[EventBus] = None,
        *,
        bit_mode: int = 64
    ):
        self.unicorn = unicorn
        self.hooks = hooks
        self.event_bus = event_bus or EventBus()
        self.bit_mode = bit_mode
        # Initialize Capstone disassembler for this CPU
        self._cs = self.make_disassembler()

    @abc.abstractmethod
    def setup_hooks(self) -> None:
        """
        Register all necessary hooks for this CPU model.
        Use `self.hooks` to install Unicorn hooks and `self.publish` to emit events.
        """
        pass

    @abc.abstractmethod
    def make_disassembler(self) -> Cs:
        """
        Construct and return a Capstone Cs instance tuned to `self.bit_mode`.
        """
        pass

    def disasm(self, code: bytes, addr: int):
        """
        Disassemble raw bytes at `addr` using the configured Capstone instance.
        """
        return self._cs.disasm(code, addr)

    def subscribe(self, event: Any, handler: Callable[..., Any], priority: int = 0) -> None:
        """
        Subscribe a handler to an event on the CPU's bus.
        """
        self.event_bus.subscribe(event, handler, priority)

    def publish(self, event: Any, *args, **kwargs) -> List[Any]:
        """
        Publish an event to the CPU's bus and return handler results.
        """
        return self.event_bus.publish(event, *args, **kwargs)
