from .device_registry import DeviceRegistry

def dump_registry_tree(registry: DeviceRegistry):
    for path, dev in registry.all().items():
        print(f"{path:30} {dev.__class__.__name__}")