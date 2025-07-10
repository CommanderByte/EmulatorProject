"""
Adapter for SYSCALL and SYSENTER instructions.
"""
from capstone.x86_const import X86_INS_SYSCALL, X86_INS_SYSENTER
from unicorn.unicorn_const import UC_HOOK_INSN
from .common import InsnHookConfig

class SyscallHook:
    CONFIG = InsnHookConfig(
        hook_type=UC_HOOK_INSN,
        insns=(X86_INS_SYSCALL, X86_INS_SYSENTER),
        priority=100,
    )

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to SYSCALL and SYSENTER instructions.

        Callback signature:
            handler(uc, insn, user_data) -> bool

        Returns:
            handle (int) of the registered hook
        """
        cfg = SyscallHook.CONFIG
        def _cb(uc, insn, user_data):
            return handler(uc, insn, user_data)
        return hooks.add_hook(
            cfg.hook_type,
            _cb,
            priority=cfg.priority,
            extra=cfg.insns
        )
