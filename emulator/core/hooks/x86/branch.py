"""
Mixin for branch trace hooks.
"""

from typing import Any, Callable
from unicorn.unicorn_const import UC_HOOK_CODE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP

from emulator.core import HookMixin


class BranchTraceHookMixin(HookMixin):
    def __init__(self, uc, *args, **kwargs):
        super().__init__(uc, *args, **kwargs)
        # Use a 32-bit disassembler by default; swap to 16-bit after mode switch if needed
        self._branch_cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self._branch_cs.detail = True

    def on_branch(
        self,
        callback: Callable[[Any, int, int, str, str, Any], bool],
        begin:      int = 1,
        end:        int = 0,
        user_data:  Any = None
    ) -> int:
        """
        Hook every basic block, disassemble it, and invoke `callback`
        on each branch (conditional or unconditional).

        callback signature:
          def callback(
              uc,            # Unicorn engine
              address: int,  # branch instruction address
              size:    int,  # branch instruction size
              mnemonic:str,  # e.g. "jmp", "je", etc.
              op_str:str,    # operand string
              user_data
          ) -> bool

        Return True in the callback to continue emulation, False to stop.

        Returns the hook handle.
        """
        def _block_cb(uc, address, size, ud):
            code = uc.mem_read(address, size)
            for insn in self._branch_cs.disasm(code, address):
                # group CS_GRP_JUMP covers jmp, je, jne, ja, etc.
                if CS_GRP_JUMP in insn.groups:
                    # invoke user callback
                    cont = callback(uc, insn.address, insn.size,
                                    insn.mnemonic, insn.op_str, ud)
                    if not cont:
                        return False
            return True

        # UC_HOOK_CODE supplies (uc, address, size, user_data)
        return self.add_hook(UC_HOOK_CODE, _block_cb, user_data, begin, end)

