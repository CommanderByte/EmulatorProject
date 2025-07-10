"""
Alias for `ExceptionHook` to emphasize interrupts.
"""
from .exception import ExceptionHook

class InterruptHook(ExceptionHook):
    pass
