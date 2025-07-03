def write_u8(buf: bytearray, offset: int, value: int):
    buf[offset] = value & 0xFF

def write_u16(buf: bytearray, offset: int, value: int):
    buf[offset]     = value & 0xFF
    buf[offset + 1] = (value >> 8) & 0xFF

def write_u32(buf: bytearray, offset: int, value: int):
    for i in range(4):
        buf[offset + i] = (value >> (8 * i)) & 0xFF

def read_u8(buf: bytes, offset: int) -> int:
    return buf[offset]

def read_u16(buf: bytes, offset: int) -> int:
    return buf[offset] | (buf[offset + 1] << 8)

def read_u32(buf: bytes, offset: int) -> int:
    return sum(buf[offset + i] << (8 * i) for i in range(4))

def encode_cf8(bus: int, device: int, function: int, register: int, enable: bool = True) -> int:
    """
    Constructs a 32-bit CONFIG_ADDRESS value to write to 0xCF8.
    """
    return (
        (0x80000000 if enable else 0x0)
        | ((bus & 0xFF) << 16)
        | ((device & 0x1F) << 11)
        | ((function & 0x07) << 8)
        | ((register & 0x3F) << 2)
    )


def decode_cf8(cf8: int) -> tuple[int, int, int, int]:
    """
    Extracts (bus, device, function, register) from a CONFIG_ADDRESS DWORD.
    """
    bus = (cf8 >> 16) & 0xFF
    device = (cf8 >> 11) & 0x1F
    function = (cf8 >> 8) & 0x07
    register = (cf8 >> 2) & 0x3F
    return (bus, device, function, register)
