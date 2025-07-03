from typing import List
from .device_registry import DeviceRegistry

def search(registry: DeviceRegistry, query: str) -> List[str]:
    return [path for path in registry.all() if query in path]


def startswith(registry: DeviceRegistry, prefix: str) -> List[str]:
    return [path for path in registry.all() if path.startswith(prefix)]