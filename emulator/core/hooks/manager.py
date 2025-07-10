import logging
from bisect import insort
from collections import defaultdict
from typing import Callable, Any, Dict, List, Tuple
from unicorn import Uc
from unicorn.unicorn_const import (
    UC_HOOK_INTR,
    UC_HOOK_INSN,
    UC_HOOK_CODE,
    UC_HOOK_BLOCK,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_PROT,
    UC_HOOK_MEM_WRITE_PROT,
    UC_HOOK_MEM_FETCH_PROT,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_FETCH,
    UC_HOOK_MEM_READ_AFTER,
    UC_HOOK_INSN_INVALID,
    UC_HOOK_EDGE_GENERATED,
    UC_HOOK_TCG_OPCODE,
    UC_HOOK_TLB_FILL,
    # Combined masks
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_PROT,
    UC_HOOK_MEM_READ_INVALID,
    UC_HOOK_MEM_WRITE_INVALID,
    UC_HOOK_MEM_FETCH_INVALID,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_VALID,
)

logger = logging.getLogger(__name__)

# Decorator to mark methods as hook callbacks
def hook(hook_type: int, *, priority: int = 0, begin: int = 1, end: int = 0, extra: tuple = ()):
    def decorator(fn: Callable):
        fn._hook_info = {
            "type": hook_type,
            "priority": priority,
            "begin": begin,
            "end": end,
            "extra": extra,
        }
        return fn
    return decorator

# Internal structure to keep callback metadata
class CallbackInfo:
    __slots__ = ("priority", "callback", "begin", "end", "extra", "handle", "hook_type", "user_data")

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
        # Sort descending by priority
        return self.priority > other.priority

    def matches(self, address: int) -> bool:
        # Check if the event address falls within the registered range
        return self.begin <= address < (self.end or float("inf"))

# Map each hook type to its wrapper factory
_WRAPPERS: Dict[int, Callable[["HookManager", Callable], Callable]] = {
        UC_HOOK_INTR                 : lambda mgr, fn: mgr.wrap_intr(fn),
        UC_HOOK_INSN                 : lambda mgr, fn: mgr.wrap_insn(fn),
        UC_HOOK_CODE                 : lambda mgr, fn: mgr.wrap_code(fn),
        UC_HOOK_BLOCK                : lambda mgr, fn: mgr.wrap_block(fn),
        UC_HOOK_MEM_READ             : lambda mgr, fn: mgr.wrap_mem_access(fn),
        UC_HOOK_MEM_WRITE            : lambda mgr, fn: mgr.wrap_mem_access(fn),
        UC_HOOK_MEM_FETCH            : lambda mgr, fn: mgr.wrap_mem_access(fn),
        UC_HOOK_MEM_READ_AFTER       : lambda mgr, fn: mgr.wrap_mem_after(fn),
        UC_HOOK_MEM_READ_UNMAPPED    : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_WRITE_UNMAPPED   : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_FETCH_UNMAPPED   : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_READ_PROT        : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_WRITE_PROT       : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_FETCH_PROT       : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_INSN_INVALID         : lambda mgr, fn: mgr.wrap_insn_invalid(fn),
        UC_HOOK_EDGE_GENERATED       : lambda mgr, fn: mgr.wrap_edge_generated(fn),
        UC_HOOK_TCG_OPCODE           : lambda mgr, fn: mgr.wrap_tcg_opcode(fn),
        UC_HOOK_TLB_FILL             : lambda mgr, fn: mgr.wrap_tlb_fill(fn),
        # Combined bitmasks just reuse the same wrappers:
        UC_HOOK_MEM_UNMAPPED         : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_PROT             : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_READ_INVALID     : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_WRITE_INVALID    : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_FETCH_INVALID    : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_INVALID          : lambda mgr, fn: mgr.wrap_mem_invalid(fn),
        UC_HOOK_MEM_VALID            : lambda mgr, fn: mgr.wrap_mem_access(fn),
    }

class HookManager:
    """
    Wraps the Unicorn hook API and tracks registered hooks.
    """

    def __init__(self, uc: Uc):
        self.uc = uc
        self._registry: Dict[int, List[CallbackInfo]] = defaultdict(list)
        self._handles: Dict[int, CallbackInfo] = {}


    # You can add wrappers for PROT, INTR, SYSCALL, MMIO_READ, etc. similarly.

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
        Register a new hook: wrap the Python callback into the correct C-callback and
        install it into Unicorn. Return the Unicorn handle.
        """
        factory = _WRAPPERS.get(hook_type)
        if not factory:
            raise ValueError(f"No wrapper for hook type {hook_type}")
        c_callback = factory(self, callback)
        # user_data passed directly to unicorn
        handle = self.uc.hook_add(hook_type, c_callback, user_data, begin, end, *extra)

        info = CallbackInfo(
            priority, callback, begin, end, extra, handle, hook_type, user_data
        )
        insort(self._registry[hook_type], info)
        self._handles[handle] = info
        return handle

    def remove_hook(self, handle: int) -> None:
        """
        Remove a specific hook by its Unicorn handle.
        """
        info = self._handles.pop(handle, None)
        if not info:
            return
        # remove from unicorn and registry
        self.uc.hook_del(handle)
        self._registry[info.hook_type] = [ci for ci in self._registry[info.hook_type] if ci.handle != handle]

    def list_hooks(self) -> List[Dict[str, Any]]:
        """
        List all currently registered hooks with metadata.
        """
        return [
            {
                "handle": handle,
                "type": info.hook_type,
                "priority": info.priority,
                "range": (info.begin, info.end),
                "callback": info.callback,
                "user_data": info.user_data,
            }
            for handle, info in self._handles.items()
        ]

    def clear_all(self) -> None:
        """
        Remove all hooks registered through this manager.
        """
        for handle in list(self._handles.keys()):
            self.remove_hook(handle)

    def discover_and_register(self, owner: Any) -> None:
        """
        Auto-discover any methods on `owner` marked with @hook and register them.
        """
        for attr in dir(owner):
            fn = getattr(owner, attr)
            info = getattr(fn, "_hook_info", None)
            if not info:
                continue
            self.add_hook(
                info["type"],
                fn,
                priority=info["priority"],
                begin=info["begin"],
                end=info["end"],
                user_data=None,
                extra=info["extra"],
            )

    # --- wrapper factories ------------------------------------------------

    def wrap_insn(self, user_cb):
        # UC_HOOK_INSN: bool(*)(uc_engine, void*)
        def _cb(uc, user_data):
            return user_cb(uc, user_data)

        return _cb

    def wrap_code(self, user_cb):
        # UC_HOOK_CODE: void(*)(uc_engine, uint64 address, size_t size, void*)
        def _cb(uc, addr, size, user_data):
            return user_cb(uc, addr, size, user_data)

        return _cb

    def wrap_block(self, user_cb):
        # UC_HOOK_BLOCK: void(*)(uc_engine, uint64 address, uint64 size, void*)
        def _cb(uc, addr, size, user_data):
            return user_cb(uc, addr, size, user_data)

        return _cb

    def wrap_mem_access(self, user_cb):
        # UC_HOOK_MEM_ACCESS_CB: void(*)(uc_engine, int access, uint64 addr, int size, int64 value, void*)
        def _cb(uc, access, addr, size, value, user_data):
            return user_cb(uc, access, addr, size, value, user_data)

        return _cb

    def wrap_mem_invalid(self, user_cb):
        # UC_HOOK_MEM_INVALID_CB: bool(*)(uc_engine, int access, uint64 addr, int size, int64 value, void*)
        def _cb(uc, access, addr, size, value, user_data):
            return user_cb(uc, access, addr, size, value, user_data)

        return _cb

    def wrap_mem_after(self, user_cb):
        # UC_HOOK_MEM_READ_AFTER: void(*)(uc_engine, int access, uint64 addr, int size, int64 value, void*)
        def _cb(uc, access, addr, size, value, user_data):
            return user_cb(uc, access, addr, size, value, user_data)

        return _cb

    def wrap_insn_invalid(self, user_cb):
        # UC_HOOK_INSN_INVALID: bool(*)(uc_engine, uc_err, void*)
        def _cb(uc, errno, user_data):
            return user_cb(uc, errno, user_data)

        return _cb

    def wrap_edge_generated(self, user_cb):
        # UC_HOOK_EDGE_GENERATED: void(*)(uc_engine, uc_tb *from, uc_tb *to, void*)
        def _cb(uc, from_tb, to_tb, user_data):
            return user_cb(uc, from_tb, to_tb, user_data)

        return _cb

    def wrap_tcg_opcode(self, user_cb):
        # UC_HOOK_TCG_OPCODE: void(*)(uc_engine, uint64 offset, uint64 size, uint64 insn, void*)
        def _cb(uc, offset, size, insn, user_data):
            return user_cb(uc, offset, size, insn, user_data)

        return _cb

    def wrap_tlb_fill(self, user_cb):
        # UC_HOOK_TLB_FILL: void(*)(uc_engine, uint64 vaddr, unsigned width, void*)
        def _cb(uc, vaddr, width, user_data):
            return user_cb(uc, vaddr, width, user_data)

        return _cb


    def wrap_intr(self,user_cb):
        # UC_HOOK_INTR: void(*)(uc_engine, int irq, void*)
        def _cb(uc, irq, user_data):
            user_cb(uc, irq, user_data)

        return _cb