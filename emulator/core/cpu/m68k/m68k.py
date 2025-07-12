from unicorn.unicorn_const import UC_HOOK_CODE

from emulator.core.cpu.base_cpu import CPU


class M68KCPU(CPU):
    """
    M68K-specific CPU: sets up code-execution hooks.
    """
    def __init__(self, unicorn, hooks):
        super().__init__(unicorn, hooks)
        # Optional: configure UC_ARCH_M68K/UC_MODE_M68K_000 on `uc` here

    def setup_hooks(self):
        def on_code(uc, addr, size, user_data):
            # custom M68K code hook logic
            return True

        self.hooks.add_hook(
            UC_HOOK_CODE,
            on_code,
            priority=5,
            begin=0x0,
            end=0xFFFFFFFF
        )