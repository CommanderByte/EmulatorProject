from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_16

BIOS_BASE = 0xFFC00000
BIOS_SIZE = 0x400000
RESET_VECTOR = 0xFFFFFFF0


class IOHandler:
    def __init__(self):
        print("🟢 Initializing IO handler")
        self.handlers = []

    def register(self, handler_fn):
        print(f"🟢 Registering IO handler {handler_fn}")
        self.handlers.append(handler_fn)

    def dispatch(self, uc, port, size, value, is_write):
        for handler in self.handlers:
            if handler(uc, port, size, value, is_write):
                return True
        return False


class MMIOHandler:
    def __init__(self):
        print("🟢 Initializing MMIO handler")
        self.ranges = []

    def register(self, base, size, read_fn=None, write_fn=None):
        print(f"🟢 Registering MMIO range 0x{base:08X} - 0x{base + size:08X} handler {read_fn} {write_fn}")
        self.ranges.append((base, base + size, read_fn, write_fn))

    def handle(self, uc, access, address, size, value):
        for start, end, rfn, wfn in self.ranges:
            if start <= address < end:
                if access == UC_MEM_READ_UNMAPPED and rfn:
                    return rfn(uc, address, size)
                elif access == UC_MEM_WRITE_UNMAPPED and wfn:
                    return wfn(uc, address, size, value)
        print(f"[MMIO {access}] Unhandled at 0x{address:08X}")
        return True  # Allow access


class BIOSEmulator:
    def __init__(self, bios_path):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_16)
        self.io = IOHandler()
        self.mmio = MMIOHandler()

        # Load BIOS
        print("🟢 Loading BIOS")
        with open(bios_path, "rb") as f:
            self.bios = f.read()

        BIOS_TOP_BASE = 0xF0000
        BIOS_TOP_SIZE = 0x10000  # 64 KiB

        # Slice the top 64K from the full BIOS image
        bios_top = self.bios[-BIOS_TOP_SIZE:]

        # Map it to 0xF0000
        self.uc.mem_map(BIOS_TOP_BASE, BIOS_TOP_SIZE)
        self.uc.mem_write(BIOS_TOP_BASE, bios_top)

        FLASH_BASE = 0xFFC00000
        FLASH_SIZE = 0x400000  # 4 MiB

        self.uc.mem_map(FLASH_BASE, FLASH_SIZE)
        self.uc.mem_write(FLASH_BASE, self.bios)

        # Set up the real-mode reset vector
        self.uc.reg_write(UC_X86_REG_CS, 0xF000)
        self.uc.reg_write(UC_X86_REG_IP, 0xFFF0)

        TPM_BASE = 0xFED40000
        TPM_SIZE = 0x1000  # can go larger if needed (e.g. 0x5000)

        self.uc.mem_map(TPM_BASE, TPM_SIZE)
        # Optional: fill with 0xFF or zeroes
        self.uc.mem_write(TPM_BASE, b"\x00" * TPM_SIZE)

        # Add hooks
        print("🟢 Adding hooks")
        #self.uc.hook_add(UC_HOOK_IO, self._hook_io)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mmio)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)

    REGS_TO_PRINT = [
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_ESP, UC_X86_REG_EBP,
        UC_X86_REG_EIP, UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS
    ]

    REG_NAMES = {
        UC_X86_REG_EAX: "EAX", UC_X86_REG_EBX: "EBX", UC_X86_REG_ECX: "ECX", UC_X86_REG_EDX: "EDX",
        UC_X86_REG_ESI: "ESI", UC_X86_REG_EDI: "EDI", UC_X86_REG_ESP: "ESP", UC_X86_REG_EBP: "EBP",
        UC_X86_REG_EIP: "EIP", UC_X86_REG_CS: "CS", UC_X86_REG_DS: "DS", UC_X86_REG_SS: "SS"
    }

    def _hook_code(self, uc, address, size, user_data=None):
        code = uc.mem_read(address, size)
        for insn in self.cs.disasm(code, address):
            # Print registers
            regs = {name: uc.reg_read(reg) for reg, name in self.REG_NAMES.items()}
            reg_dump = " | ".join([f"{k}={v:08X}" for k, v in regs.items()])
            print(f"📍 0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")
            print(f"🔧 REGISTERS: {reg_dump}")

            # Check for MSR opcodes
            if code[:2] == b"\x0f\x32":  # RDMSR
                ecx = uc.reg_read(UC_X86_REG_ECX)
                print(f"📥 RDMSR → MSR 0x{ecx:08X}")
                # Dummy value logic:
                eax = 0
                edx = 0
                if ecx == 0x1B:
                    eax = 0x00000100  # Bit 8 set, for example
                uc.reg_write(UC_X86_REG_EAX, eax)
                uc.reg_write(UC_X86_REG_EDX, edx)
                # Skip instruction
                uc.reg_write(UC_X86_REG_EIP, uc.reg_read(UC_X86_REG_EIP) + 2)
                return

            elif code[:2] == b"\x0f\x30":  # WRMSR
                ecx = uc.reg_read(UC_X86_REG_ECX)
                eax = uc.reg_read(UC_X86_REG_EAX)
                edx = uc.reg_read(UC_X86_REG_EDX)
                value = (edx << 32) | eax
                print(f"📤 WRMSR → MSR 0x{ecx:08X} = 0x{value:016X}")
                if ecx == 0x1B and value & (1 << 8):
                    print("🧿 MSR 0x1B bit 8 (LME?) is being set.")
                # Skip instruction
                uc.reg_write(UC_X86_REG_EIP, uc.reg_read(UC_X86_REG_EIP) + 2)
                return

            # Optional: highlight memory access or unknown instructions
            try:
                print(f"🧠 Instruction at 0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")
            except:
                print(f"🧠 Instruction at 0x{insn.address:08X}: {insn.mnemonic}")

    def _hook_io(self, uc, port, size, value, is_write, user_data=None):
        if not self.io.dispatch(uc, port, size, value, is_write):
            direction = "WRITE" if is_write else "READ"
            print(f"[IO {direction}] Unhandled port 0x{port:04X}, size={size}, val=0x{value:08X}")

    def _hook_mmio(self, uc, access, addr, size, value, user_data=None):
        return self.mmio.handle(uc, access, addr, size, value)



    def run(self, max_instr=100_000):
        print(f"🟢 Running BIOS from {RESET_VECTOR:#x}")
        try:
            self.uc.emu_start(0xFFFFFFF0, BIOS_BASE + BIOS_SIZE, count=1000)
        except UcError as e:
            print(f"💥 Unicorn error: {e}")

    def step(self):
        self.uc.emu_start(self.uc.reg_read(UC_X86_REG_EIP), BIOS_BASE + BIOS_SIZE, count=1)
        pass

def pci_config_hook(uc, port, size, value, is_write):
    if port in [0xCF8, 0xCFC, 0xCFA, 0xCFB, 0xCFD, 0xCFE, 0xCFF]:
        direction = "WRITE" if is_write else "READ"
        print(f"[PCI {direction}] port=0x{port:04X}, val=0x{value:08X}, size={size}")
        return True
    return False

if __name__ == "__main__":
    bios = BIOSEmulator("emulator/data/BIOS_t610_1_20.bin")
    bios.io.register(pci_config_hook)
    print(f"EIP is 0x{bios.uc.reg_read(UC_X86_REG_EIP):08X}")
    bios.run()
    print(f"EIP is 0x{bios.uc.reg_read(UC_X86_REG_EIP):08X}")
    for i in range(10000):
        print(f"EIP is 0x{bios.uc.reg_read(UC_X86_REG_EIP):08X}")
        bios.step()
    print(f"EIP is 0x{bios.uc.reg_read(UC_X86_REG_EIP):08X}")