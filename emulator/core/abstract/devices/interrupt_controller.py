import logging
from typing import Callable, Optional, Literal, List
from threading import Lock

logger = logging.getLogger(__name__)

TriggerType = Literal["edge", "level"]

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
        self.trigger_types: List[TriggerType] = ["level"] * irq_count
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
        """
        Raises an IRQ (Interrupt Request) signal based on the specified index and the
        configured behavior (edge-triggered or level-triggered). The method checks
        whether the IRQ is masked, and if so, logs the information and exits without
        taking any further actions. For unmasked IRQs, it processes the signal based
        on its trigger type and handles the assertion accordingly.

        :param irq: The index of the IRQ to be raised.
        :type irq: int
        :return: None
        """
        with self.lock:
            if self.irq_masked[irq]:
                logger.debug(f"🚫 IRQ {irq} is masked, ignored")
                return

            if self.trigger_types[irq] == "edge":
                logger.debug(f"📣 IRQ {irq} edge triggered")
                if self.irq_callback:
                    self.irq_callback(irq, True)
            elif not self.irq_lines[irq]:
                self.irq_lines[irq] = True
                logger.debug(f"📣 IRQ {irq} level asserted")
                if self.irq_callback:
                    self.irq_callback(irq, True)

    def lower_irq(self, irq: int):
        """
        Clears or lowers the specified interrupt request (IRQ) line. If the IRQ line is currently active,
        this method sets it to inactive and logs the operation. Additionally, if an IRQ callback is defined,
        it triggers the callback with the IRQ index and the new state (set to False).

        :param irq: Index of the interrupt request line to clear. Must be an integer.
        :type irq: int
        :return: None
        """
        with self.lock:
            if self.irq_lines[irq]:
                self.irq_lines[irq] = False
                logger.debug(f"🔕 IRQ {irq} cleared")
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
        """
        Sets the trigger type for a specified IRQ (Interrupt Request Line). The trigger
        type determines how the hardware or software will respond to the specified
        interrupts, whether it is triggered by a level or edge signal.

        :param irq: The number of the IRQ to configure.
        :type irq: int
        :param trigger_type: The type of trigger for the IRQ, either 'edge' or 'level'.
        :type trigger_type: TriggerType
        :return: None
        """
        with self.lock:
            if trigger_type not in ("edge", "level"):
                raise ValueError("Invalid trigger type: must be 'edge' or 'level'")
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
