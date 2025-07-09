#!/usr/bin/env python3
import logging
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_16
from unicorn import UC_ARCH_X86, UC_MODE_32, UC_PROT_READ, UC_PROT_EXEC, UC_PROT_WRITE, UC_PROT_ALL
from unicorn.x86_const import UC_X86_INS_PUSH, UC_X86_INS_POPF, UC_X86_INS_POP, UC_X86_INS_PUSHF

from emulator.platforms.x86.bios_x86 import setup_bios_x86

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s: %(message)s'
)

# import your refactored setup function & core emulator

def main():
    # 1. Locate BIOS image (pass path on cmdline or default to bios.bin)
    bios_path = sys.argv[1] if len(sys.argv) > 1 else 'emulator/data/BIOS_t610_1_20.bin'
    try:
        with open(bios_path, 'rb') as f:
            bios = f.read()
    except FileNotFoundError:
        print(f"ERROR: BIOS image not found at {bios_path}")
        sys.exit(1)

    # 2. Build and configure your emulator + hooks
    emu = setup_bios_x86(bios_path)
    # map BIOS region and write the blob
    print(len(bios))
    emu.map_memory(0xFFC00000, len(bios), perms=UC_PROT_READ | UC_PROT_EXEC, content=bios)

    CHUNK_SIZE = 0x10_0000
    emu.map_memory(0x00000, 0x10_0000,
                   perms=UC_PROT_READ | UC_PROT_EXEC ,content=bios[-CHUNK_SIZE:])

    # 3. Example “generic” hook: dump every basic block
    # create one disassembler for reuse
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = False  # turn on if you want operand/lift info

    def log_block(uc, address, size, user_data):
        # read the raw bytes of the block
        code = uc.mem_read(address, size)
        # disassemble and print each instruction
        for insn in md.disasm(code, address):
            print(f"0x{insn.address:08X}:  {insn.mnemonic}\t{insn.op_str}")

    # hook every basic block
    emu.on_code(log_block)

    # 4. Example “x86-specific” hook: trap all CPUID calls
    def fake_cpuid(uc, user_data):
        # 1) Emulated CPUID behavior:
        eax = uc.reg_read(uc.regs.EAX)
        if eax == 0:
            uc.reg_write(uc.regs.EAX, 1)
            uc.reg_write(uc.regs.EBX, 0x756e6547)  # "Genu"
            uc.reg_write(uc.regs.EDX, 0x49656e69)  # "ineI"
            uc.reg_write(uc.regs.ECX, 0x6c65746e)  # "ntel"

        # 2) Figure out the instruction size so we can skip it

        # 4) Return True to continue
        return True
    emu.on_cpuid(fake_cpuid)

    def find_free_page(memory_map: dict[int, tuple[int, int]],
                       *,
                       page_size: int = 0x1000,
                       start_addr: int = 0x0100_0000) -> int:
        """
        Given memory_map: base -> (size, perms), find the first gap
        ≥ page_size at or above start_addr.
        """
        # build sorted list of (base, end)
        intervals = sorted(
            (base, base + size)
            for base, (size, _) in memory_map.items()
            if base + size > start_addr
        )
        logger.debug(f"sorted intervals: {intervals}")
        candidate = start_addr
        for base, end in intervals:
            if candidate + page_size <= base:
                return candidate
            candidate = max(candidate, end)
        return candidate

    def handle_mem_invalid(uc, access, addr, size, value, user_data):
        print(f"[MEM_INVALID] addr=0x{addr:08X}, size={size}")
        return True

    emu.on_mem_invalid(handle_mem_invalid,begin=0,end=0xFFFFFFFF)

    def handle_mem_prot(uc, access, addr, size, value, user_data):
        print(f"[MEM_PROT] addr=0x{addr:08X}, size={size}")
        return True

    def skip_stack_insn(uc, access, addr, size, user_data):
        # just advance EIP past the instruction; don't touch any regs or mem
        uc.reg_write(uc.regs.EIP, addr + size)
        return True

    # hook all the x86 push/pop variants
    #emu.on_instruction(UC_X86_INS_PUSH, skip_stack_insn)
    #emu.on_instruction(UC_X86_INS_POP, skip_stack_insn)

    # register your new handler before emu.run(...)
    emu.on_mem_prot(handle_mem_prot,begin=0,end=0xFFFFFFFF)

    # Print memory layout
    for region in emu.uc.mem_regions():
        start, end, perms = region
        print(f"REGION: 0x{start:08X}-0x{end - 1:08X} perms=0x{perms:X}")

    # 5. start
    print(f"Reset vector = {0xFFFFFFF0} → starting emulation")
    emu.run(0xFFFFFFF0, 0x100000)  # until you hit a hook or timeout

if __name__ == '__main__':
    main()
