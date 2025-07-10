"""
Adapter for CPU exception/interrupt events.
"""
from unicorn.unicorn_const import UC_HOOK_INTR
from .common import InsnHookConfig

class ExceptionHook:
    CONFIG = InsnHookConfig(
        hook_type=UC_HOOK_INTR,
        insns=(),
        priority=0,
    )

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to all interrupts/exceptions.

        Callback signature:
            handler(uc, irq, user_data)
        """
        cfg = ExceptionHook.CONFIG
        def _cb(uc, irq, user_data):
            return handler(uc, irq, user_data)
        return hooks.add_hook(
            cfg.hook_type,
            _cb,
            priority=cfg.priority
        )
