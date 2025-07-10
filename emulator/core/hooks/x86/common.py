"""
Shared configuration dataclass for x86 instruction hooks.
"""
from dataclasses import dataclass
from typing import Tuple
from unicorn.unicorn_const import *

@dataclass(frozen=True)
class InsnHookConfig:
    """
    Defines a Unicorn hook type with associated instruction IDs and priority.

    Attributes:
      hook_type: one of UC_HOOK_* constants
      insns: tuple of Capstone instruction IDs
      priority: integer, higher runs first
    """
    hook_type: int
    insns: Tuple[int, ...]
    priority: int = 100