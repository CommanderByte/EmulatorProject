"""
Adapter for CPUID instruction hook.
"""
from capstone.x86_const import X86_INS_CPUID
from unicorn.unicorn_const import UC_HOOK_INSN
from .common import InsnHookConfig

class CpuidHook:
    CONFIG = InsnHookConfig(
        hook_type=UC_HOOK_INSN,
        insns=(X86_INS_CPUID,),
        priority=100,
    )

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to CPUID instruction.

        Handler receives (uc, leaf) and returns (eax, ebx, ecx, edx).
        """
        cfg = CpuidHook.CONFIG
        def _cb(uc, insn, user_data):
            leaf = uc.reg_read(uc.const.X86_REG_RAX)
            eax, ebx, ecx, edx = handler(uc, leaf)
            uc.reg_write(uc.const.X86_REG_RAX, eax)
            uc.reg_write(uc.const.X86_REG_RBX, ebx)
            uc.reg_write(uc.const.X86_REG_RCX, ecx)
            uc.reg_write(uc.const.X86_REG_RDX, edx)
            return True
        return hooks.add_hook(
            cfg.hook_type,
            _cb,
            priority=cfg.priority,
            extra=cfg.insns
        )
