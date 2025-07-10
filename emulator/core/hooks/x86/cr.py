"""
Adapter for MOV to/from control/debug registers.
Cannot hook this with INSNs as not supported in unicorn (QEMU limitation).
"""

class CrHook:

    @staticmethod
    def register(hooks, handler) -> int:
        """
        Subscribe `handler` to MOV_CR and MOV_DR instructions.
        """
        raise NotImplementedError(
            "MOV_CR/MOV_DR cannot be hooked directly via INS hooks; "
            "use the CODE_INSN event to catch these."
        )