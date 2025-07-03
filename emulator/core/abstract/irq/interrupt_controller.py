import logging
from typing import Callable, Optional, Literal, List
from threading import Lock

from emulator.core.abstract.irq.trigger_type import TriggerType, EdgeTrigger, Polarity

logger = logging.getLogger(__name__)

class InterruptController:
    """
    Represents an interrupt controller managing IRQ lines, triggers, masks, priorities,
    and associated callbacks.

    This class provides mechanisms to manage a fixed number of interrupt request (IRQ)
    lines with associated states, triggers, and configurations. It ensures thread safety
    and allows registering callback functions to handle IRQ events.

    :ivar irq_count: The total number of IRQ lines managed by the controller.
    :type irq_count: int
    :ivar irq_lines: A list representing the activation state of each IRQ line.
    :type irq_lines: List[bool]
    :ivar trigger_types: A list defining the trigger type (e.g., level) for each IRQ line.
    :type trigger_types: List[TriggerType]
    :ivar irq_masked: A list indicating whether each IRQ line is currently masked.
    :type irq_masked: List[bool]
    :ivar irq_priority: A list of priorities assigned to each IRQ line. Lower index signifies
        higher priority.
    :type irq_priority: List[int]
    :ivar lock: A threading lock to ensure thread-safe access to properties and operations.
    :type lock: threading.Lock
    :ivar irq_callback: An optional callable accepting an IRQ line number and state, to
        handle IRQ-related operations.
    :type irq_callback: Optional[Callable[[int, bool], None]]
    """

    def __init__(self, irq_count: int = 256):
        """
        Represents an interrupt controller managing IRQ lines, triggers, masks, priorities,
        and associated callbacks.

        This class provides mechanisms to manage a fixed number of interrupt request (IRQ)
        lines with associated states, triggers, and configurations. It ensures thread safety
        and allows registering callback functions to handle IRQ events.

        :param irq_count: The number of IRQ lines to initialize and manage (default is 256).

        :ivar irq_count: The total number of IRQ lines managed by the controller.
        :ivar irq_lines: A list representing the activation state of each IRQ line.
        :ivar trigger_types: A list defining the trigger type (e.g., level) for each IRQ line.
        :ivar irq_masked: A list indicating whether each IRQ line is currently masked.
        :ivar irq_priority: A list of priorities assigned to each IRQ line. Lower index signifies
            higher priority.
        :ivar lock: A threading lock to ensure thread-safe access to properties and operations.
        :ivar irq_callback: An optional callable accepting an IRQ line number and state, to
            handle IRQ-related operations.
        """
        self.irq_count = irq_count
        self.irq_lines = [False] * irq_count
        self.trigger_types: List[TriggerType] = [
            TriggerType(edge=EdgeTrigger.LEVEL, polarity=Polarity.ACTIVE_LOW)
            for _ in range(irq_count)
        ]

        self.irq_masked = [False] * irq_count
        self.irq_priority = list(range(irq_count))  # Default priority: lower index = higher priority
        self.lock = Lock()
        self.irq_callback: Optional[Callable[[int, bool], None]] = None

    def connect_handler(self, callback: Callable[[int, bool], None]):
        """
        Connects an interrupt request (IRQ) handler by assigning a callback function.
        The callback function will be invoked when the associated event occurs. This
        method is used to set up logic that will handle specific hardware or system
        interrupts.

        :param callback: The callback function to execute when the IRQ is triggered.
            It should accept two parameters: an integer representing the interrupt
            code and a boolean indicating the state.
        :type callback: Callable[[int, bool], None]
        :return: None
        """
        self.irq_callback = callback
        logger.info("🔌 IRQ handler connected")

    def raise_irq(self, irq: int):
        with self.lock:
            if self.irq_masked[irq]:
                logger.debug(f"🚫 IRQ {irq} is masked, ignored")
                return

            trig = self.trigger_types[irq]

            # EDGE
            if trig.edge == EdgeTrigger.EDGE or trig.edge in (EdgeTrigger.RISING, EdgeTrigger.FALLING,
                                                              EdgeTrigger.BOTH):
                logger.debug(f"📣 IRQ {irq} edge-triggered ({trig})")
                if self.irq_callback:
                    self.irq_callback(irq, True)

            # LEVEL
            elif trig.edge == EdgeTrigger.LEVEL:
                active_state = trig.polarity == Polarity.ACTIVE_HIGH
                if self.irq_lines[irq] != active_state:
                    self.irq_lines[irq] = active_state
                    logger.debug(f"📣 IRQ {irq} level-triggered ({trig})")
                    if self.irq_callback:
                        self.irq_callback(irq, True)

    def lower_irq(self, irq: int):
        with self.lock:
            trig = self.trigger_types[irq]

            if trig.edge == EdgeTrigger.LEVEL:
                inactive_state = trig.polarity == Polarity.ACTIVE_HIGH
                if self.irq_lines[irq] == inactive_state:
                    self.irq_lines[irq] = not inactive_state
                    logger.debug(f"🔕 IRQ {irq} level deasserted")
                    if self.irq_callback:
                        self.irq_callback(irq, False)

            elif trig.edge in (EdgeTrigger.RISING, EdgeTrigger.FALLING, EdgeTrigger.BOTH, EdgeTrigger.EDGE):
                # Edge-triggered interrupts are assumed to auto-clear after callback
                logger.debug(f"🔕 IRQ {irq} edge complete")
                if self.irq_callback:
                    self.irq_callback(irq, False)

    def is_irq_active(self, irq: int) -> bool:
        """
        Determines whether a specific interrupt request (IRQ) line is currently active.

        This method checks if the specified IRQ line is currently active in the system.
        An active IRQ line typically means that the corresponding interrupt is in effect
        and requires handling.

        :param irq: The IRQ line to check.
        :type irq: int
        :return: A boolean indicating whether the specified IRQ line is active.
        :rtype: bool
        """
        return self.irq_lines[irq]

    def clear_all(self):
        """
        Clears all active interrupt request (IRQ) lines and updates their state.

        This method iterates through all interrupt request lines and sets their state
        to inactive (False). If `irq_callback` is defined, it is invoked with the IRQ
        identifier and its updated state as arguments. A log message is recorded after
        clearing all IRQs.

        :raises: Does not explicitly raise any errors.

        :return: None
        """
        with self.lock:
            for irq, active in enumerate(self.irq_lines):
                if active:
                    self.irq_lines[irq] = False
                    if self.irq_callback:
                        self.irq_callback(irq, False)
            logger.info("🧹 All IRQs cleared")

    def set_mask(self, irq: int, masked: bool):
        """
        Sets the mask state for a specified interrupt request (IRQ) in a thread-safe manner.

        Locks the current instance to ensure that changes to the IRQ mask state are
        managed without concurrent modification issues. After updating the mask state,
        logs the action for debugging purposes.

        :param irq: Interrupt request identifier to be updated
        :param masked: Boolean value indicating the desired mask state for the IRQ
        :return: None
        """
        with self.lock:
            self.irq_masked[irq] = masked
            logger.debug(f"🔧 IRQ {irq} mask set to {masked}")

    def set_trigger_type(self, irq: int, trigger_type: TriggerType):
        with self.lock:
            self.trigger_types[irq] = trigger_type
            logger.debug(f"⚙️ IRQ {irq} trigger type set to {trigger_type}")


    def set_priority(self, irq: int, priority: int):
        """
        Set the priority for a given IRQ (Interrupt Request).

        This method modifies the priority of a specified IRQ, ensuring that the operation
        is performed atomically by acquiring a lock. The priority value is updated in the
        `irq_priority` dictionary. A debug-level log message is generated to reflect the
        updated priority value of the IRQ.

        :param irq: The identifier for the IRQ whose priority is being set.
        :param priority: The priority level to assign to the specified IRQ.
        :return: None
        """
        with self.lock:
            self.irq_priority[irq] = priority
            logger.debug(f"⬆️ IRQ {irq} priority set to {priority}")

    def get_highest_priority_irq(self) -> Optional[int]:
        """
        Determine the IRQ line with the highest priority that is currently active and not masked.

        This method evaluates all active interrupt request (IRQ) lines to determine
        the one with the highest priority that is not masked. It ensures safe access
        to the data structure by acquiring a thread lock during execution.

        :return: The index of the IRQ line with the highest priority, or None if no
            lines are active and unmasked.
        :rtype: Optional[int]
        """
        with self.lock:
            active_irqs = [irq for irq, active in enumerate(self.irq_lines) if active and not self.irq_masked[irq]]
            if not active_irqs:
                return None
            return min(active_irqs, key=lambda irq: self.irq_priority[irq])
