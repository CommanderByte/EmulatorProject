"""
Adapter for RDMSR and WRMSR instructions.
"""
from typing import Tuple

from capstone.x86_const import X86_INS_RDMSR, X86_INS_WRMSR
from unicorn.unicorn_const import UC_HOOK_INSN
from .common import InsnHookConfig

class MsrHook:
    CONFIG_RD = InsnHookConfig(hook_type=UC_HOOK_INSN, insns=(X86_INS_RDMSR,), priority=100)
    CONFIG_WR = InsnHookConfig(hook_type=UC_HOOK_INSN, insns=(X86_INS_WRMSR,), priority=100)

    @staticmethod
    def register(hooks, rd_handler, wr_handler) -> Tuple[int, int]:
        """
        Subscribe `rd_handler` to RDMSR and `wr_handler` to WRMSR.

        rd_handler(uc, msr_id) -> int
        wr_handler(uc, msr_id, value) -> None
        """
        rd_cfg = MsrHook.CONFIG_RD
        wr_cfg = MsrHook.CONFIG_WR
        def _rd(uc, insn, user_data):
            msr = uc.reg_read(uc.const.X86_REG_ECX)
            val = rd_handler(uc, msr)
            uc.reg_write(uc.const.X86_REG_RAX, val & 0xFFFFFFFF)
            uc.reg_write(uc.const.X86_REG_RDX, val >> 32)
            return True
        def _wr(uc, insn, user_data):
            msr = uc.reg_read(uc.const.X86_REG_ECX)
            lo = uc.reg_read(uc.const.X86_REG_RAX)
            hi = uc.reg_read(uc.const.X86_REG_RDX)
            wr_handler(uc, msr, (hi << 32) | lo)
            return True
        h1 = hooks.add_hook(rd_cfg.hook_type, _rd, priority=rd_cfg.priority, extra=rd_cfg.insns)
        h2 = hooks.add_hook(wr_cfg.hook_type, _wr, priority=wr_cfg.priority, extra=wr_cfg.insns)
        return (h1, h2)
