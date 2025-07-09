"""
Mixin for I/O port hooks.
"""
from typing import Any, Callable
from unicorn.unicorn_const import UC_HOOK_INSN
from unicorn.x86_const import UC_X86_INS_IN, UC_X86_INS_OUT
from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from capstone.x86 import X86_OP_IMM, X86_OP_REG

from emulator.core import HookMixin


class IOPortHookMixin(HookMixin):
    def __init__(self, uc, *args, **kwargs):
        super().__init__(uc, *args, **kwargs)
        # one 16-bit-capable disassembler for IN/OUT
        self._io_cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self._io_cs.detail = True

    def on_port_in(
        self,
        port: int,
        callback: Callable[[Any, int, Any], int],
        begin: int = 1,
        end:   int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook IN instructions for a given port.
        callback signature: (uc, port, user_data) -> int  # must return the value to read
        """
        def _cb(uc, user_data):
            pc   = uc.reg_read(uc.regs.EIP)
            code = uc.mem_read(pc, 6)               # IN imm8 is up to 2 bytes, but we read a few
            insns = list(self._io_cs.disasm(code, pc, count=1))
            if not insns or insns[0].id != UC_X86_INS_IN:
                return True

            insn = insns[0]
            # operand[1] is the port (IMM or REG=DX)
            op = insn.operands[1]
            op_port = op.imm if op.type == X86_OP_IMM else uc.reg_read(uc.regs.DX)
            if op_port != port:
                return True

            # get the value to return
            val = callback(uc, port, user_data)
            # write into the destination register (operand[0])
            dst = insn.operands[0]
            if dst.type == X86_OP_REG:
                uc.reg_write(dst.reg, val)

            # skip the instruction
            uc.reg_write(uc.regs.EIP, pc + insn.size)
            return True

        return self.add_hook(
            UC_HOOK_INSN, _cb, user_data, begin, end, UC_X86_INS_IN
        )

    def on_port_out(
        self,
        port: int,
        callback: Callable[[Any, int, int, Any], bool],
        begin: int = 1,
        end:   int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook OUT instructions for a given port.
        callback signature: (uc, port, value, user_data) -> bool
        """
        def _cb(uc, user_data):
            pc   = uc.reg_read(uc.regs.EIP)
            code = uc.mem_read(pc, 6)
            insns = list(self._io_cs.disasm(code, pc, count=1))
            if not insns or insns[0].id != UC_X86_INS_OUT:
                return True

            insn = insns[0]
            # operand[0] is port (IMM or REG=DX), operand[1] is source reg
            port_op = insn.operands[0]
            op_port = port_op.imm if port_op.type == X86_OP_IMM else uc.reg_read(uc.regs.DX)
            if op_port != port:
                return True

            # read the source register value
            src = insn.operands[1]
            val = uc.reg_read(src.reg) if src.type == X86_OP_REG else 0

            # invoke user callback (allow returning False to stop)
            keep_going = callback(uc, port, val, user_data)

            # skip the instruction
            uc.reg_write(uc.regs.EIP, pc + insn.size)
            return bool(keep_going)

        return self.add_hook(
            UC_HOOK_INSN, _cb, user_data, begin, end, UC_X86_INS_OUT
        )