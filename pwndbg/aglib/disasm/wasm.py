from __future__ import annotations

from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.wasm_const import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.disasm.arch
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator

WASM_CONDITIONAL_BRANCHES = {
    WASM_INS_BR_IF,
}

class WasmDisassemblyAssistant(pwndbg.aglib.disasm.arch.DisassemblyAssistant):

    def __init__(self, architecture) -> None:
        super().__init__(architecture)

    @override
    def _prepare(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Prepare is called before emulation.
        # At this point, we want to read the value of the ctr register.
        # This is because branch instructions might mutate ctr within the emulator, which the read_register_name may fetch from
        # The _conditional() function is called after emulation is stepped, so to read the original
        # value of CTR, we have to read it beforehand.

        if instruction.id in WASM_CONDITIONAL_BRANCHES:
            instruction.groups.add(CS_GRP_JUMP)

        if instruction.id in (WASM_INS_END,WASM_INS_RETURN):
            instruction.groups.add(CS_GRP_RET)

