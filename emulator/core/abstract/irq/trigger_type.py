from dataclasses import dataclass
from enum import Enum, auto

class EdgeTrigger(Enum):
    LEVEL = auto()
    RISING = auto()
    FALLING = auto()
    BOTH = auto()
    EDGE = BOTH

class Polarity(Enum):
    ACTIVE_HIGH = auto()
    ACTIVE_LOW = auto()


@dataclass(frozen=True)
class TriggerType:
    """
    Represents a full IRQ trigger configuration, combining edge/level
    type with signal polarity.
    """
    edge: EdgeTrigger
    polarity: Polarity

    def __str__(self):
        return f"{self.edge.name.lower()} / {self.polarity.name.lower()}"
