import logging
from typing import Callable, List, Dict, Any
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_FETCH, Uc

logger = logging.getLogger(__name__)

class HookManager:
    """Lightweight wrapper for Unicorn hook registration.

    Attributes
    ----------
    uc : Uc
        Unicorn engine instance used for hook registration.
    hooks : List[Dict[str, Any]]
        Internal list of registered hooks with metadata.
    """

    def __init__(self, uc: Uc):
        """Create a hook manager for the given Unicorn instance.

        Parameters
        ----------
        uc : Uc
            Unicorn instance to manage hooks for.
        """
        self.uc = uc
        self.hooks: List[Dict[str, Any]] = []

    def add_hook(self, hook_type: int, callback: Callable, begin: int = 1, end: int = 0, user_data: Any = None):
        """Register a hook with Unicorn and store its handle.

        Parameters
        ----------
        hook_type : int
            Hook type constant.
        callback : Callable
            Function to call when the hook triggers.
        begin : int, optional
            Start address for the hook range, defaults to ``1``.
        end : int, optional
            End address for the hook range, defaults to ``0``.
        user_data : Any, optional
            Optional data passed to the callback.

        Returns
        -------
        Optional[Any]
            Handle returned by Unicorn or ``None`` on failure.
        """
        try:
            handle = self.uc.hook_add(hook_type, callback, user_data, begin, end)
            self.hooks.append({
                "handle": handle,
                "type": hook_type,
                "callback": callback,
                "range": (begin, end),
                "user_data": user_data
            })
            logger.debug(f"✅ Hook registered: type={hook_type}, callback {callback}, range=0x{begin:X}-0x{end:X}")
            return handle
        except Exception as e:
            logger.exception(f"❌ Failed to add hook: {e} (type {hook_type}, callback {callback}, range 0x{begin:X}-0x{end:X})")

            return None

    def remove_hook(self, handle):
        """Remove a hook by handle.

        Parameters
        ----------
        handle : Any
            Hook handle previously returned by :meth:`add_hook`.
        """
        try:
            self.uc.hook_del(handle)
            self.hooks = [h for h in self.hooks if h["handle"] != handle]
            logger.debug("🗑️ Hook removed successfully")
        except Exception as e:
            logger.error(f"❌ Failed to remove hook: {e}")

    def clear_all(self):
        """Remove all registered hooks."""
        for hook in self.hooks:
            try:
                self.uc.hook_del(hook["handle"])
            except Exception as e:
                logger.warning(f"⚠️ Error removing hook: {e}")
        self.hooks.clear()
        logger.info("🧹 All hooks cleared")

    def list_hooks(self):
        """Return the list of currently registered hooks.

        Returns
        -------
        List[Dict[str, Any]]
            Details of each registered hook.
        """
        return self.hooks
