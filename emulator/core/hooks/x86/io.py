"""
Adapter for IN/OUT port I/O instructions.
"""
from capstone.x86_const import X86_INS_IN, X86_INS_OUT
from unicorn.unicorn_const import UC_HOOK_INSN
from .common import InsnHookConfig

class IoHook:
    CONFIG = InsnHookConfig(
        hook_type=UC_HOOK_INSN,
        insns=(X86_INS_IN, X86_INS_OUT),
        priority=100,
    )

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to IN and OUT instructions.

        Callback signature:
            handler(uc, insn, user_data) -> bool
        """
        cfg = IoHook.CONFIG
        def _cb(uc, insn, user_data):
            return handler(uc, insn, user_data)
        return hooks.add_hook(
            cfg.hook_type,
            _cb,
            priority=cfg.priority,
            extra=cfg.insns
        )
