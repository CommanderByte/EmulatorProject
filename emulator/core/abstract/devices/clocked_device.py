from abc import ABC, abstractmethod
from threading import Lock

class ClockedDevice(ABC):
    """
    Abstract base class for devices that operate based on clock cycles.

    This class is designed to represent devices that perform actions
    synchronously or asynchronously on receiving specific numbers of clock
    cycles. It enforces the implementation of the `clock` method, which
    is invoked to signify the passage of one or more clock cycles. Subclasses
    are expected to define their behavior when `clock` is called. The class
    optionally offers a locking mechanism for thread safety, allowing
    subclasses to handle concurrent operations if needed.

    :ivar _clock_lock: Optional lock to ensure thread-safe operation of the
                       clock method.
    :type _clock_lock: Lock
    """

    def __init__(self):
        """
        A class-level attribute initialization with optional thread safety.

        This class includes an initialization method that sets up
        a lock instance to enable thread-safe operations if required.

        Attributes:
            _clock_lock (:class:`threading.Lock`): A lock object used
            for synchronizing access to shared resources in a
            thread-safe manner.
        """
        # Optional thread safety if needed later
        self._clock_lock = Lock()

    @abstractmethod
    def clock(self, cycles: int = 1):
        """
        Simulates the passage of clock cycles in a system.

        This abstract method is used to represent the elapse of a certain number
        of clock cycles. Implementations of this method should define the behavior
        for processing or updating a system as it transitions through the given
        number of cycles. The number of cycles defaults to 1 if not specified.

        :param cycles: The number of clock cycles to elapse. Defaults to 1.
        :type cycles: int
        :return: None
        """
        ...
