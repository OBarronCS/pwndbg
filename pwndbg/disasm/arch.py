from __future__ import annotations

from typing import Callable

import gdb
from capstone import *  # noqa: F403

import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.color.memory as MemoryColor

# import pwndbg.gdblib.config
import pwndbg.lib.cache
from pwndbg.disasm.instruction import EnhancedOperand
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator

# Even if this is disabled, branch instructions will still have targets printed
pwndbg.gdblib.config.add_param(
    "disasm-annotations",
    True,
    """
Display annotations for instructions to provide context on operands and results
""",
)

pwndbg.gdblib.config.add_param(
    "emulate-annotations",
    True,
    """
Unicorn emulation for register and memory value annotations on instructions
""",
)

# If this is false, emulation is only used for the current instruction (if emulate-annotations is enabled)
pwndbg.gdblib.config.add_param(
    "emulate-future-annotations",
    True,
    """
Unicorn emulation to annotate instructions after the current program counter
""",
)

# Effects future instructions, as past ones have already been cached and reflect the process state at the time
pwndbg.gdblib.config.add_param(
    "disasm-telescope-depth", 3, "Depth of telescope for disasm annotations"
)

# In disasm view, long telescoped strings might cause lines wraps
pwndbg.gdblib.config.add_param(
    "disasm-telescope-string-length",
    50,
    "Number of characters in strings to display in disasm annotations",
)

# DEBUG_ENHANCEMENT = False
DEBUG_ENHANCEMENT = True

groups = {v: k for k, v in globals().items() if k.startswith("CS_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("CS_OP_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

for value1, name1 in dict(access).items():
    for value2, name2 in dict(access).items():
        # novermin
        access.setdefault(value1 | value2, f"{name1} | {name2}")


# Enhances disassembly with memory values & symbols by adding member variables to an instruction
# The only public method that should be called is "enhance"
# The enhance function is passed an instance of the Unicorn emulator
#  and will .single_step() it to determine operand values before and after executing the instruction
class DisassemblyAssistant:
    # Registry of all instances, {architecture: instance}
    assistants: dict[str, DisassemblyAssistant] = {}

    def __init__(self, architecture: str) -> None:
        if architecture is not None:
            self.assistants[architecture] = self

        # The Capstone type for the "Operand" depends on the Arch
        # Types found in capstone.ARCH_NAME.py, such as capstone.x86.py
        self.op_handlers: dict[
            int, Callable[[PwndbgInstruction, EnhancedOperand, Emulator], int | None]
        ] = {
            CS_OP_IMM: self.parse_immediate,  # Return immediate value
            CS_OP_REG: self.parse_register,  # Return value of register
            # Handler for memory references (as dictated by Capstone), such as first operand of "mov qword ptr [rbx + rcx*4], rax"
            CS_OP_MEM: self.parse_memory,  # Return parsed address, do not dereference
        }

        # Return a string corresponding to operand. Used to reduce code duplication while printing
        # REG type wil return register name, "RAX"
        self.op_names: dict[int, Callable[[PwndbgInstruction, EnhancedOperand], str | None]] = {
            CS_OP_IMM: self.immediate_string,
            CS_OP_REG: self.register_string,
            CS_OP_MEM: self.memory_string,
        }

    @staticmethod
    def for_current_arch():
        return DisassemblyAssistant.assistants.get(pwndbg.gdblib.arch.current, None)

    # Mutates the "instruction" object
    @staticmethod
    def enhance(instruction: PwndbgInstruction, emu: Emulator = None) -> None:
        # Assumed that the emulator's pc is at the instruction's address

        if DEBUG_ENHANCEMENT:
            print(
                f"Start enhancing instruction at {hex(instruction.address)} - {instruction.mnemonic} {instruction.op_str}"
            )

        # For both cases below, we still step the emulation so we can use it to determine jump target
        # in the pwndbg.disasm.near() function. Then, set emu to None so we don't use it for annotation
        if emu and not bool(pwndbg.gdblib.config.emulate_annotations):
            emu.single_step(check_instruction_valid=False)
            emu = None

        # Disable emulation for future annotations based on setting
        if (
            emu
            and pwndbg.gdblib.regs.pc != instruction.address
            and not bool(pwndbg.gdblib.config.emulate_future_annotations)
        ):
            emu.single_step(check_instruction_valid=False)
            emu = None

        # Ensure emulator's program counter is at the correct location. Failure indicates a bug.
        if emu:
            if DEBUG_ENHANCEMENT:
                print(
                    f"{hex(pwndbg.gdblib.regs.pc)=} {hex(emu.pc)=} and {hex(instruction.address)=}"
                )
                assert emu.pc == instruction.address

            if emu.pc != instruction.address:
                emu = None

        enhancer: DisassemblyAssistant = DisassemblyAssistant.assistants.get(
            pwndbg.gdblib.arch.current, generic_assistant
        )

        # This function will .single_step the emulation
        if not enhancer.enhance_operands(instruction, emu):
            emu = None
            if DEBUG_ENHANCEMENT:
                print(f"Emulation failed at {instruction.address=:#x}")

        enhancer.enhance_conditional(instruction, emu)

        enhancer.enhance_next(instruction, emu)

        if bool(pwndbg.gdblib.config.disasm_annotations):
            enhancer.set_annotation_string(instruction, emu)

        if DEBUG_ENHANCEMENT:
            print(enhancer.dump(instruction))
            print("Done enhancing")

    # Subclasses for specific architecture should override this
    def set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        The goal of this function is to set the `annotation` field of the instruction,
        which is the string to be printed in a disasm view.
        """
        return None

    def enhance_operands(self, instruction: PwndbgInstruction, emu: Emulator) -> bool:
        """
        Enhances the operands by determining values and symbols

        When emulation is enabled, this will `single_step` the emulation to determine the value of registers
        before and after the instrution has executed.

        For each operand explicitly written to or read from (instruction.operands), sets the following fields:

            operand.before_value
                Integer value of the operand before instruction executes.
                None if cannot be resolved/reasoned about.

            operand.after_value
                Integer value of the operand after instruction executes.
                Only set when emulation is enabled. Otherwise None.
                This is relevent if we read and write to the same registers within an instruction

            operand.symbol:
                Resolved symbol name for this operand, if .before_value is set, else None.

            operand.str:
                String representing the operand

        Return False if emulation fails (so we don't use it in additional enhancement steps)
        """

        # Populate the "operands" list of the instruction
        # Set before_value, symbol, and str
        for op in instruction.operands:
            # Retrieve the value, either an immediate, from a register, or from memory
            op.before_value = self.op_handlers.get(op.type, lambda *a: None)(instruction, op, emu)
            if op.before_value is not None:
                op.before_value &= pwndbg.gdblib.arch.ptrmask
                op.symbol = pwndbg.gdblib.symbol.get(op.before_value)

        # Execute the instruction and set after_value
        if emu and None not in emu.single_step(check_instruction_valid=False):
            # after_value
            for op in instruction.operands:
                # Retrieve the value, either an immediate, from a register, or from memory
                op.after_value = self.op_handlers.get(op.type, lambda *a: None)(
                    instruction, op, emu
                )
                if op.after_value is not None:
                    op.after_value &= pwndbg.gdblib.arch.ptrmask
        else:
            emu = None

        # Set .str value of operands, after emulation has been completed
        for op in instruction.operands:
            op.str = self.op_names.get(op.type, lambda *a: None)(instruction, op)

        return emu is not None

    # Determine if the program counter of the process equals the address of the function being executed.
    # If so, it means we can safely reason and read from registers and memory to represent values that
    # we can add to the .info_string. This becomes relevent when NOT emulating, and is meant to
    # allow more details when the PC is at the instruction being enhanced
    def can_reason_about_process_state(self, instruction: PwndbgInstruction) -> bool:
        return instruction.address == pwndbg.gdblib.regs.pc

    # Delegates to "read_register", which takes Capstone ID for register.
    def parse_register(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ) -> int | None:
        reg = operand.reg
        return self.read_register(instruction, reg, emu)

    # Determine memory address of operand (Ex: in x86, mov rax, [rip + 0xd55], would return $rip_after_instruction+0xd55)
    # Subclasses override for specific architectures
    def parse_memory(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ) -> int | None:
        return None

    def parse_immediate(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ):
        return operand.imm

    # Read value in register. Return None if cannot reason about the value in the register.
    # Different architectures use registers in different patterns, so it is best to
    # override this to get to best behavior for a given architecture. See x86.py as example.
    def read_register(self, instruction: PwndbgInstruction, operand_id: int, emu: Emulator) -> int | None:
        # operand_id is the ID internal to Capstone
        regname: str = instruction.cs_insn.reg_name(operand_id)
        
        if emu:
            # Will return the value of register after executing the instruction
            value = emu.read_register(regname)
            if DEBUG_ENHANCEMENT:
                print(f"Register in emulation returned {regname}={hex(value)}")
            return value
        elif self.can_reason_about_process_state(instruction):
            # When instruction address == pc, we can reason about all registers.
            # The values will just reflect values prior to executing the instruction, instead of after,
            # which is relevent if we are writing to this register.
            # However, the information can still be useful for display purposes.
            if DEBUG_ENHANCEMENT:
                print(f"Read value from process register: {pwndbg.gdblib.regs[regname]}")
            return pwndbg.gdblib.regs[regname]
        else:
            return None


    # Read memory of given size, taking into account emulation and being able to reason about the memory location
    def read_memory(
        self,
        address: int,
        size: int,
        instruction: PwndbgInstruction,
        operand: EnhancedOperand,
        emu: Emulator,
    ) -> int | None:
        address_list, did_telescope = self.telescope(
            address, 1, instruction, operand, emu, read_size=size
        )
        if did_telescope:
            if len(address_list) >= 2:
                return address_list[1]
        return None
    

    # Pass in a operand and it's value, and determine the actual value used during an instruction
    # Helpful for cases like  `cmp    byte ptr [rip + 0x166669], 0`, where first operand could be
    # a register or a memory value to dereference, and we want the actual value used.
    # Return None if cannot dereference in the case it's a memory address
    def resolve_used_value(
        self, value: int | None, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ) -> int | None:
        if value is None:
            return None

        if operand.type == CS_OP_REG or operand.type == CS_OP_IMM:
            return value
        elif operand.type == CS_OP_MEM:
            return self.read_memory(value, operand.size, instruction, operand, emu)

        return None
    

    # Dereference an address recursively - takes into account emulation.
    # If cannot dereference safely, returns a list with just the passed in address.
    # Note that this means the last value might be a pointer, while the format functions expect
    # to receive a list of deferenced pointers with the last value being a non-pointer
    #
    # This is why we return a Tuple[list[int], did_telescope: boolean]
    #   The first value is the list of addresses, the second is a boolean to indicate if telescoping occured,
    #   or if the address was just sent back as the only value in a list.
    #   This is important for the formatting function, as we pass the boolean there to indicate if during
    #   enhancement of the last value in the chain we should attempt to dereference it or not.
    #   We shouldn't dereference during enhancement if we cannot reason about the value in memory
    #
    # The list that the function returns is guaranteed have len >= 1
    def telescope(
        self,
        address: int,
        limit: int,
        instruction: PwndbgInstruction,
        operand: EnhancedOperand,
        emu: Emulator,
        read_size: int = None,
    ) -> tuple[list[int], bool]:
        # It is assumed proper checks have been made BEFORE calling this function so that `address`
        # is not None, and so that in the case of non-emulation, pwndbg.chain.format will return values
        # accurate to the program state after the instruction has executed. If just using operand values,
        # this should work automatically, as `enhance_operands` only sets values it can reason about.
        #
        # can_read_process_state indicates if the current program counter of the process is the same as the instruction
        # The way to determine this varies between architectures (some arches have PC a constant offset to instruction address),
        # so subclasses need to specify

        can_read_process_state = self.can_reason_about_process_state(instruction)

        if emu:
            return (emu.telescope(address, limit, read_size=read_size), True)
        elif can_read_process_state:
            # Can reason about memory in this case.

            if read_size is not None and read_size != pwndbg.gdblib.arch.ptrsize:
                result = [address]

                size_type = pwndbg.gdblib.typeinfo.get_type(read_size)
                try:
                    read_value = int(pwndbg.gdblib.memory.poi(size_type, address))
                    result.append(read_value)
                except gdb.MemoryError:
                    pass

                return (result, True)

            else:
                return (pwndbg.chain.get(address, limit=limit), True)
        elif not can_read_process_state or operand.type == CS_OP_IMM:
            # If the target address is in a non-writeable map, we can pretty safely telescope
            # This is best-effort to give a better experience
            page = pwndbg.gdblib.vmmap.find(address)
            if page and not page.write:
                return (pwndbg.chain.get(address, limit=limit), True)

        # We cannot telescope, but we can still return the address.
        # Just without any further information
        return ([address], False)



    # Dispatch to the appropriate format handler. Pass the list returned by `telescope()` to this function
    def telescope_format_list(
        self, addresses: list[int], limit: int, emu: Emulator, enhance_can_dereference: bool
    ) -> str:
        # It is assumed proper checks have been made BEFORE calling this function so that pwndbg.chain.format
        #  will return values accurate to the program state at the time of instruction executing.

        enhance_string_len = int(pwndbg.gdblib.config.disasm_telescope_string_length)

        if emu:
            return emu.format_telescope_list(
                addresses, limit, enhance_string_len=enhance_string_len
            )
        else:
            # We can format, but in some cases we may not be able to reason about memory, so don't allow
            # it to dereference to last value in memory (we can't determine what value it is)
            return pwndbg.chain.format(
                addresses,
                limit=limit,
                enhance_can_dereference=enhance_can_dereference,
                enhance_string_len=enhance_string_len,
            )



    def enhance_conditional(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        Adds a ``condition`` field to the instruction.

        If the instruction is always executed unconditionally, the value
        of the field is ``None``.

        If the instruction is executed conditionally, and we can be absolutely
        sure that it will be executed, the value of the field is ``True``.
        Generally, this implies that it is the next instruction to be executed.

        In all other cases, it is set to ``False``.
        """
        c = self.condition(instruction, emu)

        if c:
            c = True
        elif c is not None:
            c = False

        instruction.condition = c

    # Subclasses should override
    def condition(self, instruction: PwndbgInstruction, emu: Emulator) -> bool | None:
        return False

    def enhance_next(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        Set the `next` and `target` field of the instruction.

        By default, it is set to the address of the next linear
        instruction.

        `next` is the address that the PC would be upon using the GDB `nexti` command,
        `target` is the jump target whether or not the jump is taken, like `stepi` and assuming the jump is taken.

        If the instruction is a non-"call" branch and either:
        - Is unconditional, or is conditional and is known to be taken, a
        - Is conditional, but is known to be taken

        And the target can be resolved, it is set to the address
        of the jump target.

        """
        next_addr: int | None = None

        if emu:
            # Use emulator to determine the next address if we can
            # Only use it to determine non-call's for .next
            if CS_GRP_CALL not in instruction.groups_set:
                next_addr = emu.pc
        elif instruction.condition is True or instruction.is_unconditional_jump:
            # If .condition is true, then this might be a conditional jump (there are some other instructions that run conditionall though)
            # or, if this is a unconditional jump, we will try to resolve the .next
            next_addr = self.resolve_target(instruction, emu)

        if next_addr is None:
            next_addr = instruction.address + instruction.size

        # Determine the target of this address, allowing call instructions
        instruction.target = self.resolve_target(instruction, emu, call=True)

        instruction.next = next_addr & pwndbg.gdblib.arch.ptrmask

        if instruction.target is None:
            instruction.target = instruction.next
        else:
            instruction.target_string = MemoryColor.get_address_or_symbol(instruction.target)

        if (
            instruction.operands
            and instruction.operands[0].before_value
            and instruction.operands[0].type == CS_OP_IMM
        ):
            instruction.target_const = True

    # This is the default implementation. Subclasses can override this. See x86.py as example
    def resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        """
        Architecture-specific hook point for enhance_next.

        Returns the value of the instruction pointer assuming this instruction executes (and any conditional jumps are taken)
        
        "call" specifies if we allow this to resolve call instruction targets
        """

        if CS_GRP_CALL in instruction.groups:
            if not call:
                return None
        elif CS_GRP_JUMP not in instruction.groups:
            return None


        # At this point, all operands have been resolved.
        # Assume only single-operand jumps.
        if len(instruction.operands) != 1:
            return None

        op = instruction.operands[0]
        addr = self.resolve_used_value(op.before_value, instruction, op, emu)
        if addr:
            addr &= pwndbg.gdblib.arch.ptrmask

        if addr is None:
            return None

        return int(addr)

    def dump(self, instruction: PwndbgInstruction):
        """
        Debug-only method.
        """
        return repr(instruction)

    # String functions assume the .before_value and .after_value have been set
    def immediate_string(self, instruction, operand) -> str:
        value = operand.before_value

        if abs(value) < 0x10:
            return "%i" % value

        return "%#x" % value

    # Return colorized register string
    def register_string(self, instruction: PwndbgInstruction, operand: EnhancedOperand):
        reg = operand.reg
        name = C.register(instruction.cs_insn.reg_name(reg).upper())

        # If using emulation and we determined the value didn't change, don't colorize
        if (
            operand.before_value is not None
            and operand.after_value is not None
            and operand.before_value == operand.after_value
        ):
            return name
        else:
            return C.register_changed(name)

    # Example: return "[_IO_2_1_stdin_+16]", where the address/symbol is colorized
    def memory_string(self, instruction: PwndbgInstruction, operand: EnhancedOperand):
        if operand.before_value is not None:
            return f"[{MemoryColor.get_address_or_symbol(operand.before_value)}]"
        else:
            return None



generic_assistant = DisassemblyAssistant(None)
