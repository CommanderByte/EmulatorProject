import logging
from typing import Callable, Any, Dict, List
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

class HookManager:
    """
    Wraps the Unicorn hook API and tracks registered hooks.
    """

    def __init__(self, uc: Uc):
        self.uc = uc
        # handle -> metadata
        self._hooks: Dict[int, Dict[str, Any]] = {}

    # --- wrapper factories ------------------------------------------------

    def _wrap_intr(self, user_cb):
        # UC_HOOK_INTR: void(*)(uc_engine, int irq, void*)
        def _cb(uc, irq, user_data):
            user_cb(uc, irq, user_data)
        return _cb

    def _wrap_insn(self, user_cb):
        # UC_HOOK_INSN: bool(*)(uc_engine, void*)
        def _cb(uc, user_data):
            return user_cb(uc, user_data)
        return _cb

    def _wrap_code(self, user_cb):
        # UC_HOOK_CODE: void(*)(uc_engine, uint64 address, size_t size, void*)
        def _cb(uc, addr, size, user_data):
            return user_cb(uc, addr, size, user_data)
        return _cb

    def _wrap_block(self, user_cb):
        # UC_HOOK_BLOCK: void(*)(uc_engine, uint64 address, uint64 size, void*)
        def _cb(uc, addr, size, user_data):
            return user_cb(uc, addr, size, user_data)
        return _cb

    def _wrap_mem_access(self, user_cb):
        # UC_HOOK_MEM_ACCESS_CB: void(*)(uc_engine, int access, uint64 addr, int size, int64 value, void*)
        def _cb(uc, access, addr, size, value, user_data):
            return user_cb(uc, access, addr, size, value, user_data)
        return _cb

    def _wrap_mem_invalid(self, user_cb):
        # UC_HOOK_MEM_INVALID_CB: bool(*)(uc_engine, int access, uint64 addr, int size, int64 value, void*)
        def _cb(uc, access, addr, size, value, user_data):
            return user_cb(uc, access, addr, size, value, user_data)
        return _cb

    def _wrap_mem_after(self, user_cb):
        # UC_HOOK_MEM_READ_AFTER: void(*)(uc_engine, int access, uint64 addr, int size, int64 value, void*)
        def _cb(uc, access, addr, size, value, user_data):
            return user_cb(uc, access, addr, size, value, user_data)
        return _cb

    def _wrap_insn_invalid(self, user_cb):
        # UC_HOOK_INSN_INVALID: bool(*)(uc_engine, uc_err, void*)
        def _cb(uc, errno, user_data):
            return user_cb(uc, errno, user_data)
        return _cb

    def _wrap_edge_generated(self, user_cb):
        # UC_HOOK_EDGE_GENERATED: void(*)(uc_engine, uc_tb *from, uc_tb *to, void*)
        def _cb(uc, from_tb, to_tb, user_data):
            return user_cb(uc, from_tb, to_tb, user_data)
        return _cb

    def _wrap_tcg_opcode(self, user_cb):
        # UC_HOOK_TCG_OPCODE: void(*)(uc_engine, uint64 offset, uint64 size, uint64 insn, void*)
        def _cb(uc, offset, size, insn, user_data):
            return user_cb(uc, offset, size, insn, user_data)
        return _cb

    def _wrap_tlb_fill(self, user_cb):
        # UC_HOOK_TLB_FILL: void(*)(uc_engine, uint64 vaddr, unsigned width, void*)
        def _cb(uc, vaddr, width, user_data):
            return user_cb(uc, vaddr, width, user_data)
        return _cb

    # You can add wrappers for PROT, INTR, SYSCALL, MMIO_READ, etc. similarly.


    _WRAPPERS = {
        UC_HOOK_INTR:                _wrap_intr,
        UC_HOOK_INSN:                _wrap_insn,
        UC_HOOK_CODE:                _wrap_code,
        UC_HOOK_BLOCK:               _wrap_block,
        UC_HOOK_MEM_READ:            _wrap_mem_access,
        UC_HOOK_MEM_WRITE:           _wrap_mem_access,
        UC_HOOK_MEM_FETCH:           _wrap_mem_access,
        UC_HOOK_MEM_READ_AFTER:      _wrap_mem_after,
        UC_HOOK_MEM_READ_UNMAPPED:   _wrap_mem_invalid,
        UC_HOOK_MEM_WRITE_UNMAPPED:  _wrap_mem_invalid,
        UC_HOOK_MEM_FETCH_UNMAPPED:  _wrap_mem_invalid,
        UC_HOOK_MEM_READ_PROT:       _wrap_mem_invalid,
        UC_HOOK_MEM_WRITE_PROT:      _wrap_mem_invalid,
        UC_HOOK_MEM_FETCH_PROT:      _wrap_mem_invalid,
        UC_HOOK_INSN_INVALID:        _wrap_insn_invalid,
        UC_HOOK_EDGE_GENERATED:      _wrap_edge_generated,
        UC_HOOK_TCG_OPCODE:          _wrap_tcg_opcode,
        UC_HOOK_TLB_FILL:            _wrap_tlb_fill,
        # Combined bitmasks just reuse the same wrappers:
        UC_HOOK_MEM_UNMAPPED:        _wrap_mem_invalid,
        UC_HOOK_MEM_PROT:            _wrap_mem_invalid,
        UC_HOOK_MEM_READ_INVALID:    _wrap_mem_invalid,
        UC_HOOK_MEM_WRITE_INVALID:   _wrap_mem_invalid,
        UC_HOOK_MEM_FETCH_INVALID:   _wrap_mem_invalid,
        UC_HOOK_MEM_INVALID:         _wrap_mem_invalid,
        UC_HOOK_MEM_VALID:           _wrap_mem_access,
    }


    def add_hook(
        self,
        hook_type: int,
        callback: Callable,
        user_data: Any = None,
        begin: int = 1,
        end:   int = 0,
        *extra
    ) -> int:
        """
        Register a Unicorn hook of type `hook_type`, wrapping your Python
        `callback` into the correct C‐callback for that hook.  Any
        `extra` positional args (e.g. instruction ID for UC_HOOK_INSN) will
        be forwarded after (user_data, begin, end).
        Returns the new handle.
        """
        factory = self._WRAPPERS.get(hook_type)
        if not factory:
            raise ValueError(f"No wrapper defined for hook type 0x{hook_type:X}")
        # bind and wrap
        c_cb = factory(self, callback)
        # register
        handle = self.uc.hook_add(hook_type, c_cb, user_data, begin, end, *extra)
        # track
        self._hooks[handle] = {
            "type":      hook_type,
            "callback":  callback,
            "wrapped":   c_cb,
            "user_data": user_data,
            "range":     (begin, end),
            "extra":     extra,
        }
        logger.debug(f"Added hook {handle}: {self._hooks[handle]}")
        return handle

    def remove_hook(self, handle: int) -> None:
        self.uc.hook_del(handle)
        self._hooks.pop(handle, None)

    def list_hooks(self) -> List[Dict[str, Any]]:
        return [{"handle": h, **md} for h, md in self._hooks.items()]

    def clear_all(self) -> None:
        for h in list(self._hooks):
            self.remove_hook(h)