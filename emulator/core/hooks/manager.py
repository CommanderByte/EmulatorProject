import logging
from bisect import insort
from collections import defaultdict
from typing import Callable, Any, Dict, List, Tuple
from unicorn import Uc
from unicorn.unicorn_const import *

logger = logging.getLogger(__name__)

class CallbackInfo:
    __slots__ = (
        "priority", "callback", "begin", "end",
        "extra", "handle", "hook_type", "user_data"
    )

    def __init__(
        self,
        priority: int,
        callback: Callable,
        begin: int,
        end: int,
        extra: Tuple[Any, ...],
        handle: int,
        hook_type: int,
        user_data: Any = None,
    ):
        self.priority = priority
        self.callback = callback
        self.begin = begin
        self.end = end
        self.extra = extra
        self.handle = handle
        self.hook_type = hook_type
        self.user_data = user_data

    def __lt__(self, other: "CallbackInfo") -> bool:
        return self.priority > other.priority

    def matches(self, address: int) -> bool:
        return self.begin <= address < (self.end or float("inf"))

class HookManager:
    """
    Wraps Unicorn hook API; register/unregister hooks explicitly without decorators.
    """
    def __init__(self, uc: Uc):
        self.uc = uc
        self._registry: Dict[int, List[CallbackInfo]] = defaultdict(list)
        self._handles: Dict[int, CallbackInfo] = {}

    @property
    def _wrappers(self) -> Dict[int, Callable[[Callable], Callable]]:
        # Map hook types to wrapper methods
        return {
            UC_HOOK_INTR: self.wrap_intr,
            UC_HOOK_INSN: self.wrap_insn,
            UC_HOOK_CODE: self.wrap_code,
            UC_HOOK_BLOCK: self.wrap_block,
            UC_HOOK_MEM_READ: self.wrap_mem_access,
            UC_HOOK_MEM_WRITE: self.wrap_mem_access,
            UC_HOOK_MEM_FETCH: self.wrap_mem_access,
            UC_HOOK_MEM_READ_AFTER: self.wrap_mem_after,
            UC_HOOK_MEM_READ_UNMAPPED: self.wrap_mem_invalid,
            UC_HOOK_MEM_WRITE_UNMAPPED: self.wrap_mem_invalid,
            UC_HOOK_MEM_FETCH_UNMAPPED: self.wrap_mem_invalid,
            UC_HOOK_MEM_READ_PROT: self.wrap_mem_invalid,
            UC_HOOK_MEM_WRITE_PROT: self.wrap_mem_invalid,
            UC_HOOK_MEM_FETCH_PROT: self.wrap_mem_invalid,
            UC_HOOK_MEM_UNMAPPED: self.wrap_mem_invalid,
            UC_HOOK_MEM_PROT: self.wrap_mem_invalid,
            UC_HOOK_MEM_READ_INVALID: self.wrap_mem_invalid,
            UC_HOOK_MEM_WRITE_INVALID: self.wrap_mem_invalid,
            UC_HOOK_MEM_FETCH_INVALID: self.wrap_mem_invalid,
            UC_HOOK_MEM_INVALID: self.wrap_mem_invalid,
            UC_HOOK_MEM_VALID: self.wrap_mem_access,
            UC_HOOK_INSN_INVALID: self.wrap_insn_invalid,
            UC_HOOK_EDGE_GENERATED: self.wrap_edge_generated,
            UC_HOOK_TCG_OPCODE: self.wrap_tcg_opcode,
            UC_HOOK_TLB_FILL: self.wrap_tlb_fill,
        }

    def add_hook(
        self,
        hook_type: int,
        callback: Callable,
        *,
        priority: int = 0,
        begin: int = 1,
        end: int = 0,
        user_data: Any = None,
        extra: Tuple[Any, ...] = (),
    ) -> int:
        """
        Register and install a hook on the Unicorn instance.
        """
        wrapper = self._wrappers.get(hook_type)
        if wrapper is None:
            raise ValueError(f"No wrapper for hook type {hook_type}")
        c_cb = wrapper(callback)
        handle = self.uc.hook_add(hook_type, c_cb, user_data, begin, end, *extra)

        info = CallbackInfo(
            priority, callback, begin, end, extra, handle, hook_type, user_data
        )
        insort(self._registry[hook_type], info)
        self._handles[handle] = info
        return handle

    def remove_hook(self, handle: int) -> None:
        info = self._handles.pop(handle, None)
        if not info:
            return
        self.uc.hook_del(handle)
        self._registry[info.hook_type] = [ci for ci in self._registry[info.hook_type] if ci.handle != handle]

    def list_hooks(self) -> List[Dict[str, Any]]:
        return [
            {
                "handle": h,
                "type": info.hook_type,
                "priority": info.priority,
                "range": (info.begin, info.end),
                "callback": info.callback,
                "user_data": info.user_data,
            }
            for h, info in self._handles.items()
        ]

    def clear_all(self) -> None:
        for h in list(self._handles):
            self.remove_hook(h)
    # --- wrapper implementations matching unicorn hook signatures ---

    def wrap_code(self, user_cb: Callable) -> Callable:
        """Hook code blocks: void(*)(Uc, uint64 address, size_t size, void*)"""
        def cb(uc, address, size, user_data):
            try:
                return user_cb(uc, address, size, user_data)
            except Exception:
                logger.exception("Error in code hook %r", user_cb)
        return cb

    def wrap_insn(self, user_cb: Callable) -> Callable:
        """Hook single instruction: bool(*)(Uc, int insn_id, void*)"""
        def cb(uc, insn, user_data):
            try:
                return user_cb(uc, insn, user_data)
            except Exception:
                logger.exception("Error in insn hook %r", user_cb)
        return cb

    def wrap_block(self, user_cb: Callable) -> Callable:
        """Hook basic block: bool(*)(Uc, uint64 address, size_t size, void*)"""
        def cb(uc, address, size, user_data):
            try:
                return user_cb(uc, address, size, user_data)
            except Exception:
                logger.exception("Error in block hook %r", user_cb)
        return cb

    def wrap_mem_access(self, user_cb: Callable) -> Callable:
        """Hook memory access: void(*)(Uc, int access, uint64 addr, int size, int64 value, void*)"""
        def cb(uc, access, addr, size, value, user_data):
            try:
                return user_cb(uc, access, addr, size, value, user_data)
            except Exception:
                logger.exception("Error in mem access hook %r", user_cb)
        return cb

    def wrap_mem_invalid(self, user_cb: Callable) -> Callable:
        """Hook invalid memory: bool(*)(Uc, int access, uint64 addr, int size, int64 value, void*)"""
        def cb(uc, access, addr, size, value, user_data):
            try:
                return user_cb(uc, access, addr, size, value, user_data)
            except Exception:
                logger.exception("Error in mem invalid hook %r", user_cb)
                return False
        return cb

    def wrap_mem_after(self, user_cb: Callable) -> Callable:
        """Hook after memory read/write: void(*)(Uc, int access, uint64 addr, int size, int64 value, void*)"""
        def cb(uc, access, addr, size, value, user_data):
            try:
                return user_cb(uc, access, addr, size, value, user_data)
            except Exception:
                logger.exception("Error in mem after hook %r", user_cb)
        return cb

    def wrap_insn_invalid(self, user_cb: Callable) -> Callable:
        """Hook invalid instruction: bool(*)(Uc, uc_err, void*)"""
        def cb(uc, errno, user_data):
            try:
                return user_cb(uc, errno, user_data)
            except Exception:
                logger.exception("Error in insn invalid hook %r", user_cb)
                return False
        return cb

    def wrap_edge_generated(self, user_cb: Callable) -> Callable:
        """Hook edge generated: void(*)(Uc, uc_tb* from, uc_tb* to, void*)"""
        def cb(uc, from_tb, to_tb, user_data):
            try:
                return user_cb(uc, from_tb, to_tb, user_data)
            except Exception:
                logger.exception("Error in edge generated hook %r", user_cb)
        return cb

    def wrap_tcg_opcode(self, user_cb: Callable) -> Callable:
        """Hook TCG opcode: void(*)(Uc, uint64 offset, uint64 size, uint64 insn, void*)"""
        def cb(uc, offset, size, insn, user_data):
            try:
                return user_cb(uc, offset, size, insn, user_data)
            except Exception:
                logger.exception("Error in tcg opcode hook %r", user_cb)
        return cb

    def wrap_tlb_fill(self, user_cb: Callable) -> Callable:
        """Hook TLB fill: void(*)(Uc, uint64 vaddr, unsigned width, void*)"""
        def cb(uc, vaddr, width, user_data):
            try:
                return user_cb(uc, vaddr, width, user_data)
            except Exception:
                logger.exception("Error in tlb fill hook %r", user_cb)
        return cb

    def wrap_intr(self, user_cb: Callable) -> Callable:
        """Hook interrupt: void(*)(Uc, int irq, void*)"""
        def cb(uc, irq, user_data):
            try:
                return user_cb(uc, irq, user_data)
            except Exception:
                logger.exception("Error in intr hook %r", user_cb)
        return cb