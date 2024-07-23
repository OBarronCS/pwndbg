from __future__ import annotations

from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.arm64 import *  # noqa: F403
from typing_extensions import override

import pwndbg.enhance
import pwndbg.gdblib.arch
import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.gdblib.disasm.instruction import EnhancedOperand
from pwndbg.gdblib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.gdblib.disasm.instruction import EnhancedOperand
from pwndbg.gdblib.disasm.instruction import InstructionCondition
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction
from pwndbg.gdblib.disasm.instruction import boolean_to_instruction_condition

# None indicates the read size depends on the target register
AARCH64_SINGLE_LOAD_INSTRUCTIONS: Dict[int, int | None] = {
    ARM64_INS_LDRB: 1,
    ARM64_INS_LDURB: 1,
    ARM64_INS_LDRSB: 1,
    ARM64_INS_LDURSB: 1,
    ARM64_INS_LDRH: 2,
    ARM64_INS_LDURH: 2,
    ARM64_INS_LDRSH: 2,
    ARM64_INS_LDURSH: 2,
    ARM64_INS_LDURSW: 4,
    ARM64_INS_LDRSW: 4,
    ARM64_INS_LDUR: None,
    ARM64_INS_LDR: None,
    ARM64_INS_LDTRB: 1,
    ARM64_INS_LDTRSB: 1,
    ARM64_INS_LDTRH: 2,
    ARM64_INS_LDTRSH: 2,
    ARM64_INS_LDTRSW: 4,
    ARM64_INS_LDTR: None,
    ARM64_INS_LDXRB: 1,
    ARM64_INS_LDXRH: 2,
    ARM64_INS_LDXR: None,
    ARM64_INS_LDARB: 1,
    ARM64_INS_LDARH: 2,
    ARM64_INS_LDAR: None,
}

AARCH64_SINGLE_STORE_INSTRUCTIONS: Dict[int, int | None] = {
    ARM64_INS_STRB: 1,
    ARM64_INS_STURB: 1,
    ARM64_INS_STRH: 2,
    ARM64_INS_STURH: 2,
    ARM64_INS_STUR: None,
    ARM64_INS_STR: None,
    # Store Register (unprivileged)
    ARM64_INS_STTRB: 1,
    ARM64_INS_STTRH: 2,
    ARM64_INS_STTR: None,
    # Store Exclusive
    ARM64_INS_STXRB: 1,
    ARM64_INS_STXRH: 2,
    ARM64_INS_STXR: None,
    # Store-Release
    ARM64_INS_STLRB: 1,
    ARM64_INS_STLRH: 2,
    ARM64_INS_STLR: None,
    # Store-Release Exclusive
    ARM64_INS_STLXRB: 1,
    ARM64_INS_STLXRH: 2,
    ARM64_INS_STLXR: None,
}

AARCH64_BIT_SHIFT_MAP: Dict[int, Callable[[int, int, int], int]] = {
    ARM64_SFT_LSL: bit_math.logical_shift_left,
    ARM64_SFT_LSR: bit_math.logical_shift_right,
    ARM64_SFT_ASR: bit_math.arithmetic_shift_right,
    ARM64_SFT_ROR: bit_math.rotate_right,
}


# These are "Extend" operations - https://devblogs.microsoft.com/oldnewthing/20220728-00/?p=106912
# They take in a number, extract a byte, halfword, or word,
# and perform a zero- or sign-extend operation.
AARCH64_EXTEND_MAP: Dict[int, Callable[[int], int]] = {
    ARM64_EXT_UXTB: lambda x: x & ((1 << 8) - 1),
    ARM64_EXT_UXTH: lambda x: x & ((1 << 16) - 1),
    ARM64_EXT_UXTW: lambda x: x & ((1 << 32) - 1),
    ARM64_EXT_UXTX: lambda x: x,  # UXTX has no effect. It extracts 64-bits from a 64-bit register.
    ARM64_EXT_SXTB: lambda x: bit_math.to_signed(x, 8),
    ARM64_EXT_SXTH: lambda x: bit_math.to_signed(x, 16),
    ARM64_EXT_SXTW: lambda x: bit_math.to_signed(x, 32),
    ARM64_EXT_SXTX: lambda x: bit_math.to_signed(x, 64),
}


def resolve_condition(condition: int, cpsr: int) -> InstructionCondition:
    """
    Given a condition and the NZCV flag bits, determine when the condition is satisfied

    The condition is a Capstone constant
    """

    n = (cpsr >> 31) & 1
    z = (cpsr >> 30) & 1
    c = (cpsr >> 29) & 1
    v = (cpsr >> 28) & 1

    condition = {
        ARM64_CC_INVALID: True,  # Capstone uses this code for the 'B' instruction, the unconditional branch
        ARM64_CC_EQ: z == 1,
        ARM64_CC_NE: z == 0,
        ARM64_CC_HS: c == 1,
        ARM64_CC_LO: c == 0,
        ARM64_CC_MI: n == 1,
        ARM64_CC_PL: n == 0,
        ARM64_CC_VS: v == 1,
        ARM64_CC_VC: v == 0,
        ARM64_CC_HI: c == 1 and z == 0,
        ARM64_CC_LS: not (c == 1 and z == 0),
        ARM64_CC_GE: n == v,
        ARM64_CC_LT: n != v,
        ARM64_CC_GT: z == 0 and n == v,
        ARM64_CC_LE: not (z == 0 and n == v),
        ARM64_CC_AL: True,
        ARM64_CC_NV: True,
    }.get(condition, False)

    return InstructionCondition.TRUE if condition else InstructionCondition.FALSE


# Parameters to each function: (value, shift_amt, bit_width)
AARCH64_BIT_SHIFT_MAP: Dict[int, Callable[[int, int, int], int]] = {
    ARM64_SFT_LSL: bit_math.logical_shift_left,
    ARM64_SFT_LSR: bit_math.logical_shift_right,
    ARM64_SFT_ASR: bit_math.arithmetic_shift_right,
    ARM64_SFT_ROR: bit_math.rotate_right,
}

# These are "Extend" operations - https://devblogs.microsoft.com/oldnewthing/20220728-00/?p=106912
# They take in a number, extract a byte, halfword, or word,
# and perform a zero- or sign-extend operation.
AARCH64_EXTEND_MAP: Dict[int, Callable[[int], int]] = {
    ARM64_EXT_UXTB: lambda x: x & ((1 << 8) - 1),
    ARM64_EXT_UXTH: lambda x: x & ((1 << 16) - 1),
    ARM64_EXT_UXTW: lambda x: x & ((1 << 32) - 1),
    ARM64_EXT_UXTX: lambda x: x,  # UXTX has no effect. It extracts 64-bits from a 64-bit register.
    ARM64_EXT_SXTB: lambda x: bit_math.to_signed(x, 8),
    ARM64_EXT_SXTH: lambda x: bit_math.to_signed(x, 16),
    ARM64_EXT_SXTW: lambda x: bit_math.to_signed(x, 32),
    ARM64_EXT_SXTX: lambda x: bit_math.to_signed(x, 64),
}


class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOV
            ARM64_INS_MOV: self._common_generic_register_destination,
            # ADR
            ARM64_INS_ADR: self._common_generic_register_destination,
            # ADRP
            ARM64_INS_ADRP: self._common_generic_register_destination,
            # ADD
            ARM64_INS_ADD: self._common_generic_register_destination,
            # SUB
            ARM64_INS_SUB: self._common_generic_register_destination,
            # CMP
            ARM64_INS_CMP: self._common_cmp_annotator_builder("cpsr", "-"),
            # CMN
            ARM64_INS_CMN: self._common_cmp_annotator_builder("cpsr", "+"),
            # TST (bitwise "and")
            ARM64_INS_TST: self._common_cmp_annotator_builder("cpsr", "&"),
            # CCMP (conditional compare)
            ARM64_INS_CCMP: self._common_cmp_annotator_builder("cpsr", ""),
            # CCMN
            ARM64_INS_CCMN: self._common_cmp_annotator_builder("cpsr", ""),
        }

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Dispatch to the correct handler
        # TODO: indexing AARCH64_SINGLE_LOAD may return NONE
        if instruction.id in AARCH64_SINGLE_LOAD_INSTRUCTIONS:
            # Handle all load instructions
            # TODO: fill this in for AARCH64
            # Rebase after the ARM instructions are done
            self._common_load_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                AARCH64_SINGLE_LOAD_INSTRUCTIONS[instruction.id],
                instruction.operands[0].str,
                instruction.operands[1].str,
            )
        else:
            self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    def generic_register_destination(self, instruction, emu: Emulator) -> None:
        """
        This function can be used to annotate instructions that have a register destination,
        which in AArch64 is always the first register. Works only while we are using emulation.

        In an ideal world, we have more specific code on a case-by-case basis to allow us to
        annotate results even when not emulating (as is done in many x86 handlers)
        """

        left = instruction.operands[0]

        # Emulating determined the value that was set in the destination register
        if left.after_value is not None:
            TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

            # Telescope the address
            telescope_addresses = super()._telescope(
                left.after_value,
                TELESCOPE_DEPTH + 1,
                instruction,
                left,
                emu,
                read_size=pwndbg.gdblib.arch.ptrsize,
            )

            if not telescope_addresses:
                return

            instruction.annotation = f"{left.str} => {super()._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)}"

    @override
    def _condition(
        self, instruction: PwndbgInstruction, emu: Emulator
    ) -> pwndbg.gdblib.disasm.arch.InstructionCondition:
        # In ARM64, only branches have the conditional code in the instruction,
        # as opposed to ARM32 which allows most instructions to be conditional
        if instruction.id == ARM64_INS_B:
            flags = super()._read_register_name(instruction, "cpsr", emu)
            if flags is not None:
                return resolve_condition(instruction.cs_insn.cc, flags)

        elif instruction.id == ARM64_INS_CBNZ:
            op_val = instruction.operands[0].before_value
            return boolean_to_instruction_condition(op_val is not None and op_val != 0)

        elif instruction.id == ARM64_INS_CBZ:
            op_val = instruction.operands[0].before_value
            return boolean_to_instruction_condition(op_val is not None and op_val == 0)

        elif instruction.id == ARM64_INS_TBNZ:
            op_val, bit = (
                instruction.operands[0].before_value,
                instruction.operands[1].before_value,
            )

            if op_val is not None and bit is not None:
                return boolean_to_instruction_condition(bool((op_val >> bit) & 1))

        elif instruction.id == ARM64_INS_TBZ:
            op_val, bit = (
                instruction.operands[0].before_value,
                instruction.operands[1].before_value,
            )

            if op_val is not None and bit is not None:
                return boolean_to_instruction_condition(not ((op_val >> bit) & 1))

        # TODO: Additionally, the "conditional comparisons" and "conditional selects" support conditional execution

        return super()._condition(instruction, emu)

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        if not bool(instruction.groups_set & ALL_JUMP_GROUPS):
            return None

        if len(instruction.operands) > 0:
            # For all AArch64 branches, the target is either an immediate or a register and is the last operand
            return instruction.operands[-1].before_value
        elif instruction.id == ARM64_INS_RET:
            # If this is a ret WITHOUT an operand, it means we should read from the LR/x30 register
            return super()._read_register_name(instruction, "lr", emu)

        return super()._resolve_target(instruction, emu, call)

    @override
    def _parse_memory(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Parse the `Arm64OpMem` Capstone object to determine the concrete memory address used.

        Three types of AArch64 memory operands:
        1. Register base with optional immediate offset
        Examples:
              ldrb   w3, [x2]
              str    x1, [x2, #0xb58]
              ldr x4,[x3], 4
        2. Register + another register with an optional shift
        Examples:
              ldrb   w1, [x9, x2]
              str x1, [x2, x0, lsl #3]
        3. Register + 32-bit register extended and shifted.
        The shift in this case is implicitly a LSL
        Examples:
              ldr x1, [x2, w22, UXTW #3]

        TODO: https://github.com/capstone-engine/capstone/issues/2230
        Bugs in Capstone - how do we fix this on our end?
        Just use the emulated value? Don't try to resolve the address?
        """

        target = 0

        # All memory operands have `base` defined
        base = self._read_register(instruction, op.mem.base, emu)
        if base is None:
            return None
        target += base

        # Add displacement (zero by default)
        target += op.mem.disp

        # If there is an index register
        if op.mem.index != 0:
            index = self._read_register(instruction, op.mem.index, emu)
            if index is None:
                return None

            # Optionally apply an extend to the index register
            if op.cs_op.ext != 0:
                index = AARCH64_EXTEND_MAP[op.cs_op.ext](index)

            # Optionally apply shift to the index register
            # This handles shifts in the extend operation as well:
            # As in the case of `ldr x1, [x2, w22, UXTW #3]`,
            # Capstone will automatically make the shift a LSL and set the value to 3
            if op.cs_op.shift.type != 0:
                # The form of instructions with a shift always apply the shift to a 64-bit value
                index = AARCH64_BIT_SHIFT_MAP[op.cs_op.shift.type](index, op.cs_op.shift.value, 64)

            target += index
        
        
        return target


    def _register_width(self, instruction: PwndbgInstruction, op: EnhancedOperand) -> int:
        return 32 if instruction.cs_insn.reg_name(op.reg)[0] == "w" else 64

    @override
    def _parse_immediate(self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator):
        """
        In AArch64, there can be an optional shift applied to constants, typically only a `LSL #12`

        Ex:
            cmp    x8, #1, lsl #12      (1 << 12)
        """
        target = op.imm
        if target is None:
            return None

        if op.cs_op.shift.type != 0:
            target = AARCH64_BIT_SHIFT_MAP[op.cs_op.shift.type](target, op.cs_op.shift.value, 64)

        return target

    @override
    def _parse_register(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Register operands can have optional extend and shift modifiers.

        Ex:
            cmp x5, x3, LSL #12         (x3 << 12)
            cmp x5, w3, SXTB 4          (Signed extend byte, then left shift 4)

        The extend operation is always applied first (if present), and then shifts take effect.
        """
        target = super()._parse_register(instruction, op, emu)
        if target is None:
            return None

        # The shift and sign-extend operations depend on the target bit width.
        # This is sometimes implicit in the target register size, which is always
        # the first operand.
        target_bit_width = (
            self._register_width(instruction, instruction.operands[0])
            if instruction.operands[0].type == CS_OP_REG
            else 64
        )

        if op.cs_op.ext != 0:
            target = AARCH64_EXTEND_MAP[op.cs_op.ext](target) & ((1 << target_bit_width) - 1)

        if op.cs_op.shift.type != 0:
            print(target, op.cs_op.shift.type, op.cs_op.shift.value)
            target = AARCH64_BIT_SHIFT_MAP[op.cs_op.shift.type](
                target, op.cs_op.shift.value, target_bit_width
            ) & ((1 << target_bit_width) - 1)

        return target


assistant = DisassemblyAssistant("aarch64")
