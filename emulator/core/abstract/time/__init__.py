"""Clock and tick based device abstractions."""

from .clocked_device import ClockedDevice
from .tick_device import TickDevice

__all__ = ["ClockedDevice", "TickDevice"]
