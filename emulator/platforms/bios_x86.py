import logging

from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_IP

from emulator.core.emulator import Emulator
from emulator.core.bus import Bus
from emulator.core.hooks import HookManager
from emulator.devices.memory.mem_mapped_rom import MemoryMappedROM
from unicorn import UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, \
    UC_MEM_WRITE_UNMAPPED, UC_MODE_32

logger = logging.getLogger(__name__)

def setup_bios_x86(bios_path: str) -> Emulator:
    BIOS_MAIN_ADDR = 0xF0000
    BIOS_MAIN_SIZE = 0x10000
    BIOS_BACKUP_ADDR = 0xFFC00000
    BIOS_BACKUP_SIZE = 0x400000
    TPM_MMIO_ADDR = 0xFED40000
    TPM_MMIO_SIZE = 0x1000

    try:
        with open(bios_path, "rb") as f:
            bios = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"BIOS file not found at path: {bios_path}")
    except IOError as e:
        raise IOError(f"Error reading BIOS file at path: {bios_path}: {e}")

    if len(bios) < BIOS_MAIN_SIZE:
        raise ValueError(f"The BIOS file is too small. Expected at least {BIOS_MAIN_SIZE} bytes, got {len(bios)}.")

    emu = Emulator(UC_ARCH_X86, UC_MODE_16)

    # Install ROM devices
    bios_rom = MemoryMappedROM(base_addr=BIOS_MAIN_ADDR, data=bios[-BIOS_MAIN_SIZE:])
    backup_rom = MemoryMappedROM(base_addr=BIOS_BACKUP_ADDR, data=bios)

    emu.add_device(bios_rom)
    emu.add_device(backup_rom)

    # Pre-map TPM MMIO (if a TPM device is added later)
    #emu.map_memory(TPM_MMIO_ADDR, TPM_MMIO_SIZE)
    md16 = Cs(CS_ARCH_X86, CS_MODE_16)  # Match UC_MODE_16 if you're in 16-bit mode
    md32 = Cs(CS_ARCH_X86, CS_MODE_32)  # Match UC_MODE_16 if you're in 16-bit mode

    def code_hook(uc, addr, size, user_data):
        try:
            code = uc.mem_read(addr, size)
            for insn in md16.disasm(code, addr):
                logger.info(f"🧠 Executing at 0x{insn.address:X}: (16) {insn.mnemonic} {insn.op_str}")
            for insn in md32.disasm(code, addr):
                logger.info(f"🧠 Executing at 0x{insn.address:X}: (32) {insn.mnemonic} {insn.op_str}")
        except Exception as e:
            logger.warning(f"⚠️ Could not disassemble at 0x{addr:X}: {e}")

    emu.hook_manager.add_hook(UC_HOOK_CODE, code_hook)

    # MMIO hook that delegates to the bus
    # def mmio_hook(uc, access, addr, size, value, user_data):
    #     is_write = access == UC_MEM_WRITE_UNMAPPED
    #     handled = bus.process_mmio_operation(addr, size, value, is_write)
    #     if not handled:
    #         logger.warning(f"⚠️ Unhandled MMIO {'write' if is_write else 'read'} at 0x{addr:X}, size={size}")
    #     return handled
    #
    # emu.add_hook(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, mmio_hook)

    logger.info("✅ x86 BIOS platform initialized")

    emu.bus.print_device_map()

    for region in emu.unicorn.mem_regions():
        print(f"{region[0]:08X} - {region[1]:08X} ({region[2]})")

    emu.unicorn.reg_write(UC_X86_REG_CS, 0xF000)
    emu.unicorn.reg_write(UC_X86_REG_IP, 0xFFF0)
    return emu
