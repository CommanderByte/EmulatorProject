"""
Mixin for code and instruction hooks.
"""
from collections.abc import Sequence
from typing import Any, Callable, Union, List
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_INSN
from .base import HookMixin

class CodeHookMixin(HookMixin):

    def on_code(
        self,
        callback: Callable[[Any, int, int, Any], bool],
        begin: int = 1,
        end:   int = 0,
        user_data: Any = None
    ) -> int:
        """
        Hook every basic-block execution in [begin, end].
        Callback signature: (uc, address, size, user_data) -> bool.
        Returns the hook handle.
        """
        return self.add_hook(UC_HOOK_CODE, callback, user_data, begin, end)

    def on_instruction(
        self,
        insn_ids: Union[int, Sequence[int]],
        callback: Callable[[Any, int, int, int, Any], bool],
        begin: int = 1,
        end:   int = 0,
        user_data: Any = None
    ) -> Union[int, List[int]]:
        """
        Hook one or more instructions by their Capstone IDs.
        - insn_ids: single ID or Sequence[int]
        - callback signature: (uc, address, size, user_data) -> bool
        - begin/end: 1,0 is Unicorn’s “anywhere” wildcard

        Returns one handle (if int) or list of handles (if Sequence).
        """
        def _add_one(iid: int) -> int:
            return self.add_hook(UC_HOOK_INSN, callback, user_data, begin, end, iid)

        if isinstance(insn_ids, Sequence):
            # filter out non-ints just in case
            ids = [i for i in insn_ids if isinstance(i, int)]
            return [_add_one(i) for i in ids]
        else:
            return _add_one(insn_ids)