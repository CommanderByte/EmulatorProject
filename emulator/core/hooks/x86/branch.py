"""
Adapter for branch, call, and return instruction hooks.
"""
from capstone.x86_const import (
    X86_INS_JMP, X86_INS_JAE, X86_INS_JNE, X86_INS_JE,
    X86_INS_JG, X86_INS_JGE, X86_INS_JL, X86_INS_JLE,
    X86_INS_CALL, X86_INS_RET,
)
from unicorn.unicorn_const import UC_HOOK_INSN
from .common import InsnHookConfig

class BranchHook:
    CONFIG = InsnHookConfig(
        hook_type=UC_HOOK_INSN,
        insns=(
            X86_INS_JMP, X86_INS_JAE, X86_INS_JNE, X86_INS_JE,
            X86_INS_JG, X86_INS_JGE, X86_INS_JL, X86_INS_JLE,
            X86_INS_CALL, X86_INS_RET,
        ),
        priority=100,
    )

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to all branch/call/ret instructions.

        Callback signature:
            handler(uc, insn, user_data) -> bool

        Returns the hook handle.
        """
        cfg = BranchHook.CONFIG
        def _cb(uc, insn, user_data):
            return handler(uc, insn, user_data)
        return hooks.add_hook(
            cfg.hook_type,
            _cb,
            priority=cfg.priority,
            extra=cfg.insns
        )
