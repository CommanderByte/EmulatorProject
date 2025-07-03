# core/bus/irq_bus.py

import logging
from typing import Optional

from emulator.core.abstract.bus.bus_participant import BusParticipant
from emulator.core.abstract.bus.interfaces.attachable_bus import AttachableBus
from emulator.core.abstract.bus.interfaces.detachable_bus import DetachableBus
from emulator.core.abstract.bus.interfaces.irq_capable_bus import IRQCapableBus
from emulator.core.abstract.irq.interrupt_raiser import InterruptRaiser
from emulator.core.abstract.irq.interrupt_source import InterruptSource
from emulator.core.bus.named_bus import NamedBus

logger = logging.getLogger(__name__)

import logging
from collections import defaultdict
from typing import Optional

from emulator.core.abstract.irq.interrupt_controller import InterruptController

logger = logging.getLogger(__name__)

class IRQBus(NamedBus, BusParticipant, AttachableBus, DetachableBus, InterruptRaiser):
    """
    Bus for managing interrupt lines and forwarding them to a central InterruptController.
    """

    def __init__(self, name: str = "irq"):
        super().__init__(name)
        self._irq_lines: dict[int, bool] = defaultdict(lambda: False)
        self.interrupt_controller: Optional[InterruptController] = None

    def get_bus_type(self) -> str:
        return "irq"

    def attach_device(self, device: object):
        # Might check later for InterruptSource if we want tight coupling
        logger.debug(f"🧩 Attached device to IRQBus: {device.__class__.__name__}")

    def detach_device(self, device: object):
        logger.debug(f"🧯 Detached device from IRQBus: {device.__class__.__name__}")

    def on_bus_connect(self, bus: "Bus"):
        logger.debug(f"🔗 IRQBus '{self.name}' connected to parent bus")

    def on_bus_disconnect(self):
        logger.debug(f"⛓️ IRQBus '{self.name}' disconnected from parent bus")

    def raise_irq(self, irq: int):
        if not self._irq_lines[irq]:
            self._irq_lines[irq] = True
            logger.info(f"⚡ IRQ {irq} asserted")
            if self.interrupt_controller:
                self.interrupt_controller.irq_changed(irq, True)

    def lower_irq(self, irq: int):
        if self._irq_lines[irq]:
            self._irq_lines[irq] = False
            logger.info(f"🔻 IRQ {irq} deasserted")
            if self.interrupt_controller:
                self.interrupt_controller.irq_changed(irq, False)

    def get_irq_state(self, irq: int) -> bool:
        return self._irq_lines[irq]

    def set_interrupt_controller(self, controller: InterruptController):
        self.interrupt_controller = controller
        logger.info(f"🧠 IRQBus '{self.name}' bound to interrupt controller: {controller.__class__.__name__}")
