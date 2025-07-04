"""Convenience access to the device registry utilities."""

from .device_registry import DeviceRegistry
from .global_registry import REGISTRY
from .aliases import resolve_alias
from .lookup import search, startswith
from .introspection import dump_registry_tree
from .capabilities import get_capabilities

__all__ = [
    "DeviceRegistry",
    "REGISTRY",
    "resolve_alias",
    "search",
    "startswith",
    "dump_registry_tree",
    "get_capabilities",
]
