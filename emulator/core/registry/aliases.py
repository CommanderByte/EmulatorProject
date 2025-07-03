# Optional: short aliases for paths
ALIASES = {
    # "uart0": "soc.uart0",
    # "main_timer": "bus.timer0",
}

def resolve_alias(name: str) -> str:
    return ALIASES.get(name, name)