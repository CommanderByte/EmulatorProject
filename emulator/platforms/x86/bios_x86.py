import logging

from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_IP

from emulator.core.emulator import Emulator
from emulator.devices.memory.mem_mapped_rom import MemoryMappedROM
from unicorn import UC_ARCH_X86, UC_MODE_16, UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED
from emulator.core.hooks import CodeHookMixin

logger = logging.getLogger(__name__)

def setup_bios_x86(bios_path: str) -> Emulator:
    """Initialize an x86 BIOS platform and return an Emulator configured with hooks."""
    # BIOS layout constants
    BIOS_MAIN_ADDR   = 0x000F0000
    BIOS_MAIN_SIZE   = 0x00010000
    BIOS_BACKUP_ADDR = 0xFFC00000
    BIOS_BACKUP_SIZE = 0x00400000
    TPM_MMIO_ADDR    = 0xFED40000
    TPM_MMIO_SIZE    = 0x00001000

    # Load BIOS image
    try:
        with open(bios_path, "rb") as f:
            bios = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"BIOS file not found: {bios_path}")
    if len(bios) < BIOS_MAIN_SIZE:
        raise ValueError(f"BIOS file too small: {len(bios)} < {BIOS_MAIN_SIZE}")

    # Instantiate emulator (inherits hook mixins internally)
    emu = Emulator(arch=UC_ARCH_X86, mode=UC_MODE_16)

    # Create and register ROM devices
    main_rom   = MemoryMappedROM(base_addr=BIOS_MAIN_ADDR,   data=bios[-BIOS_MAIN_SIZE:])
    backup_rom = MemoryMappedROM(base_addr=BIOS_BACKUP_ADDR, data=bios)
    emu.add_device(main_rom)
    emu.add_device(backup_rom)

    # Optionally pre-map TPM MMIO region
    # emu.map_memory(TPM_MMIO_ADDR, TPM_MMIO_SIZE)

    logger.info("✅ x86 BIOS platform initialized with hooks")



    # Set reset vector (CS:IP = F000:FFF0)
    emu.uc.reg_write(UC_X86_REG_CS, 0xF000)
    emu.uc.reg_write(UC_X86_REG_IP, 0xFFF0)

    return emu
