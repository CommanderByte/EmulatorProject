"""
Adapter for single-step or trace events.
"""
from unicorn.unicorn_const import UC_HOOK_INSN
from .common import InsnHookConfig

class DebugHook:
    CONFIG = InsnHookConfig(
        hook_type=UC_HOOK_INSN,
        insns=(),  # all instructions
        priority=50,
    )

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to every instruction (for tracing).

        Callback signature:
            handler(uc, insn, user_data) -> bool
        """
        cfg = DebugHook.CONFIG
        def _cb(uc, insn, user_data):
            return handler(uc, insn, user_data)
        return hooks.add_hook(
            cfg.hook_type,
            _cb,
            priority=cfg.priority
        )
