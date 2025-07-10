#!/usr/bin/env python3
import logging
import sys
from pprint import pprint

from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from capstone.x86_const import X86_OP_REG
from unicorn import UC_ARCH_X86, UC_MODE_32, UC_PROT_READ, UC_PROT_EXEC, UC_PROT_WRITE
from unicorn.unicorn_const import (
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_WRITE_PROT,
)
from unicorn.x86_const import UC_X86_INS_CPUID, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EDX, UC_X86_REG_ECX, \
    UC_X86_REG_RIP, UC_X86_REG_EIP, UC_X86_INS_MOV, UC_X86_REG_CR0

from emulator.core.emulator import Emulator
from emulator.core.hooks import hook
from emulator.platforms.x86.bios_x86 import setup_bios_x86
from emulator.core.constants import DEFAULT_PERMISSIONS

# Configure root logger
def configure_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(levelname)s: %(message)s'
    )
    logger = logging.getLogger()
    logger.debug("Logging configured at DEBUG level")


def main():
    configure_logging()
    logger = logging.getLogger(__name__)

    # 1. Locate BIOS image
    bios_path = sys.argv[1] if len(sys.argv) > 1 else 'emulator/data/BIOS_t610_1_20.bin'
    try:
        with open(bios_path, 'rb') as f:
            bios = f.read()
    except FileNotFoundError:
        logger.error("BIOS image not found at %s", bios_path)
        sys.exit(1)

    # 2. Build and configure your emulator + hooks
    emu: Emulator = setup_bios_x86(bios_path)

    # Map BIOS region
    emu.map_memory(
        0xFFC00000,
        len(bios),
        permissions=UC_PROT_READ | UC_PROT_EXEC,
        content=bios
    )

    # Map low BIOS copy
    CHUNK_SIZE = 0x10_0000
    emu.map_memory(
        0x00000,
        CHUNK_SIZE,
        permissions=UC_PROT_READ | UC_PROT_EXEC,
        content=bios[-CHUNK_SIZE:]
    )

    # 3. Generic basic-block hook
    disasm = Cs(CS_ARCH_X86, CS_MODE_16)
    disasm.detail = False

    def log_block(uc, address, size, user_data):
        code = uc.mem_read(address, size)
        for insn in disasm.disasm(code, address):
            logger.info(f"0x{insn.address:08X}: {insn.mnemonic}\t{insn.op_str}")
        return False  # continue dispatch

        # register basic-block hook
    emu.add_hook(UC_HOOK_CODE, log_block)

        # 4. x86-specific CPUID trap
    def fake_cpuid(uc, user_data):
        eax = uc.reg_read(UC_X86_REG_EAX)
        logging.info(f"CPUID EAX={eax}")
        if eax == 0:
            # return highest-supported leaf and "GenuineIntel"
            uc.reg_write(UC_X86_REG_EAX, 1)
            uc.reg_write(UC_X86_REG_EBX, 0x756e6547)
            uc.reg_write(UC_X86_REG_EDX, 0x49656e69)
            uc.reg_write(UC_X86_REG_ECX, 0x6c65746e)
        # advance RIP past CPUID instruction
        rip = uc.reg_read(UC_X86_REG_EIP)
        uc.reg_write(UC_X86_REG_EIP, rip + 2)
        return True

        # register CPUID hook
    emu.add_hook(
        UC_HOOK_INSN,
        fake_cpuid,
        extra=(UC_X86_INS_CPUID,)
    )

        # 5. Memory-invalid and protection hooks
    def handle_mem_invalid(uc, access, addr, size, value, user_data):
        logger.info(f"[MEM_INVALID] addr=0x{addr:08X}, size={size}")
        return True

    emu.add_hook(
        UC_HOOK_MEM_READ_UNMAPPED,
        handle_mem_invalid
    )

    emu.add_hook(
        UC_HOOK_MEM_WRITE_UNMAPPED,
        handle_mem_invalid
    )

        # Protection fault

    def handle_mem_prot(uc, access, addr, size, value, user_data):
        logger.info(f"[MEM_PROT] addr=0x{addr:08X}, size={size}")
        return True

    emu.add_hook(
        # XN or write-protect traps
        UC_HOOK_MEM_WRITE_PROT,
        handle_mem_prot
    )

    @hook(UC_HOOK_INSN, extra=(UC_X86_INS_MOV,))
    def catch_mov_to_cr0(uc, insn, user_data):
        # disassemble and check operands, same as our old mixin did…
        for op in insn.operands:
            if op.type == X86_OP_REG and op.reg == UC_X86_REG_CR0:
                print("CR0 was modified")
                val = uc.reg_read(UC_X86_REG_CR0)
                if val & 1:
                    print("Entered Protected Mode")
                else:
                    print("Left Protected Mode")
                # here you could call emu.stop() and re-create the Unicorn engine
        return True

    pprint(emu.list_hooks())

        # 6. Print memory regions
    for region in emu.unicorn.mem_regions():
        start, end, perms = region
        logging.info(f"REGION: 0x{start:08X}-0x{end - 1:08X} perms=0x{perms:X}")

        # 7. Start execution
    logger.info("Starting at reset vector 0xFFFFFFF0")
    emu.run(0xFFFFFFF0, 0x00100000)


if __name__ == '__main__':
    main()
