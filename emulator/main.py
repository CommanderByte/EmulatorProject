from unicorn.x86_const import UC_X86_REG_EIP

from emulator.platforms.bios_x86 import setup_bios_x86
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)

if __name__ == "__main__":
    emu = setup_bios_x86("data/BIOS_t610_1_20.bin")
    emu.run(0xFFFFFFF0, 0xFFFFFFFF,instruction_count=10000000)
    print(emu.unicorn.errno)