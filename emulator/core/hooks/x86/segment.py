"""
Adapter for MOV to/from segment registers.
"""
from capstone.x86_const import (
    X86_INS_MOV_SS, X86_INS_MOV_DS,
    X86_INS_MOV_ES, X86_INS_MOV_FS, X86_INS_MOV_GS
)
from unicorn.unicorn_const import UC_HOOK_INSN
from .common import InsnHookConfig

class SegmentHook:
    CONFIG = InsnHookConfig(
        hook_type=UC_HOOK_INSN,
        insns=(
            X86_INS_MOV_SS, X86_INS_MOV_DS,
            X86_INS_MOV_ES, X86_INS_MOV_FS, X86_INS_MOV_GS,
        ),
        priority=100,
    )

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to MOV to/from segment register instructions.

        Callback signature:
            handler(uc, insn, user_data) -> bool

        Returns:
            handle (int) of the registered hook
        """
        cfg = SegmentHook.CONFIG
        def _cb(uc, insn, user_data):
            return handler(uc, insn, user_data)
        return hooks.add_hook(
            cfg.hook_type,
            _cb,
            priority=cfg.priority,
            extra=cfg.insns
        )
