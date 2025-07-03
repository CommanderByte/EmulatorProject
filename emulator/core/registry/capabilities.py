from typing import List
# from emulator.core.abstract.meta import (
#     ResettableDevice, ConfigurableDevice, DebuggableDevice,
#     PersistableDevice, MemoryBackedDevice, UserControllableDevice
# )

# def get_capabilities(device) -> List[str]:
#     caps = []
#     if isinstance(device, ResettableDevice): caps.append("resettable")
#     if isinstance(device, ConfigurableDevice): caps.append("configurable")
#     if isinstance(device, DebuggableDevice): caps.append("debuggable")
#     if isinstance(device, PersistableDevice): caps.append("persistable")
#     if isinstance(device, MemoryBackedDevice): caps.append("memory-backed")
#     if isinstance(device, UserControllableDevice): caps.append("user-controllable")
#     return caps