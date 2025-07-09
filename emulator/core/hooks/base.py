"""
Generic mixin providing access to HookManager for devices and cores.
"""
from .manager import HookManager

class HookMixin:
    def __init__(self, uc, *args, **kwargs):
        """Initialize mixin with Unicorn engine; instantiate HookManager."""
        super().__init__(*args, **kwargs)
        self._hook_mgr = HookManager(uc)

    def add_hook(self, *args, **kwargs):
        return self._hook_mgr.add_hook(*args, **kwargs)

    def remove_hook(self, handle):
        return self._hook_mgr.remove_hook(handle)

    def list_hooks(self):
        return self._hook_mgr.list_hooks()

    def clear_hooks(self):
        return self._hook_mgr.clear_all()
