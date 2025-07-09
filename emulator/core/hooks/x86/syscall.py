"""
Mixin for system call hooks.
"""
# emulator/core/hooks/x86/syscall.py

from typing import Any, Callable, List
from unicorn.unicorn_const import UC_HOOK_INSN
from unicorn.x86_const import UC_X86_INS_SYSCALL, UC_X86_INS_INT

from emulator.core import HookMixin


class SyscallHookMixin(HookMixin):
    def on_syscall(
            self,
            callback: Callable[[Any, Any], bool],
            begin: int = 1,
            end: int = 0,
            user_data: Any = None
    ) -> List[int]:
        """
        Hook both SYSCALL and INT instructions (e.g. INT 0x80).

        callback signature: (uc, user_data) -> bool
        - Return True to continue emulation, False to stop.

        Returns a list of hook handles [h_syscall, h_int].
        """
        handles: List[int] = []
        # SYSCALL (x86_64) or SYSENTER on some CPUs
        handles.append(self.add_hook(
            UC_HOOK_INSN, callback, user_data, begin, end, UC_X86_INS_SYSCALL
        ))
        # INT instructions; inside your callback you can filter for #80
        handles.append(self.add_hook(
            UC_HOOK_INSN, callback, user_data, begin, end, UC_X86_INS_INT
        ))
        return handles
