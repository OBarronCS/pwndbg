"""
Functionality for disassmebling code at an address, or at an
address +/- a few instructions.
"""

from __future__ import annotations

import collections
import re
from typing import Any
from typing import DefaultDict
from typing import List
from typing import Union

import capstone
import gdb
from capstone import *  # noqa: F403

import pwndbg.disasm.arch
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.ida
import pwndbg.lib.cache
from pwndbg.color import message
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.disasm.instruction import make_simple_instruction
from pwndbg.disasm.arch import DEBUG_ENHANCEMENT

try:
    import pwndbg.emu.emulator
except Exception:
    pwndbg.emu = None

CapstoneArch = {
    "arm": CS_ARCH_ARM,
    "armcm": CS_ARCH_ARM,
    "aarch64": CS_ARCH_ARM64,
    "i386": CS_ARCH_X86,
    "i8086": CS_ARCH_X86,
    "x86-64": CS_ARCH_X86,
    "powerpc": CS_ARCH_PPC,
    "mips": CS_ARCH_MIPS,
    "sparc": CS_ARCH_SPARC,
    "rv32": CS_ARCH_RISCV,
    "rv64": CS_ARCH_RISCV,
}

CapstoneEndian = {
    "little": CS_MODE_LITTLE_ENDIAN,
    "big": CS_MODE_BIG_ENDIAN,
}

CapstoneMode = {4: CS_MODE_32, 8: CS_MODE_64}

CapstoneSyntax = {"intel": CS_OPT_SYNTAX_INTEL, "att": CS_OPT_SYNTAX_ATT}

# For variable-instruction-width architectures
# (x86 and amd64), we keep a cache of instruction
# sizes, and where the end of the instruction falls.
#
# This allows us to consistently disassemble backward.
VariableInstructionSizeMax = {
    "i386": 16,
    "x86-64": 16,
    "i8086": 16,
    "mips": 8,
    "rv32": 22,
    "rv64": 22,
}


# Dict of Address -> previous Address executed
backward_cache: DefaultDict[int, int] = collections.defaultdict(lambda: None)

# This allows use to retain the annotation strings from previous instructions.
# Don't use our 'cache_until' because it caches based on function arguments, but for disasm view,
# we don't want to fetch cached results in some cases.
# Dict of Address -> previously computed PwndbgInstruction
computed_instruction_cache: DefaultDict[int, PwndbgInstruction] = collections.defaultdict(
    lambda: None
)


@pwndbg.lib.cache.cache_until("objfile")
def get_disassembler_cached(arch, ptrsize: int, endian, extra=None):
    arch = CapstoneArch[arch]

    if extra is None:
        mode = CapstoneMode[ptrsize]
    else:
        mode = extra

    mode |= CapstoneEndian[endian]

    try:
        flavor = gdb.execute("show disassembly-flavor", to_string=True).lower().split('"')[1]
    except gdb.error as e:
        if str(e).find("disassembly-flavor") > -1:
            flavor = "intel"
        else:
            raise

    cs = Cs(arch, mode)
    try:
        cs.syntax = CapstoneSyntax[flavor]
    except CsError as ex:
        pass
    cs.detail = True
    return cs


def get_disassembler(pc):
    if pwndbg.gdblib.arch.current == "armcm":
        # novermin
        extra = (
            (CS_MODE_MCLASS | CS_MODE_THUMB)
            if (pwndbg.gdblib.regs.xpsr & (1 << 24))
            else CS_MODE_MCLASS
        )

    elif pwndbg.gdblib.arch.current in ("arm", "aarch64"):
        extra = CS_MODE_THUMB if (pwndbg.gdblib.regs.cpsr & (1 << 5)) else CS_MODE_ARM

    elif pwndbg.gdblib.arch.current == "sparc":
        if "v9" in gdb.newest_frame().architecture().name():
            extra = CS_MODE_V9
        else:
            # The ptrsize base modes cause capstone.CsError: Invalid mode (CS_ERR_MODE)
            extra = 0

    elif pwndbg.gdblib.arch.current == "i8086":
        extra = CS_MODE_16

    elif (
        pwndbg.gdblib.arch.current == "mips"
        and "isa32r6" in gdb.newest_frame().architecture().name()
    ):
        extra = CS_MODE_MIPS32R6

    elif pwndbg.gdblib.arch.current == "rv32":
        extra = CS_MODE_RISCV32 | CS_MODE_RISCVC  # novermin
    elif pwndbg.gdblib.arch.current == "rv64":
        extra = CS_MODE_RISCV64 | CS_MODE_RISCVC  # novermin

    else:
        extra = None

    return get_disassembler_cached(
        pwndbg.gdblib.arch.current, pwndbg.gdblib.arch.ptrsize, pwndbg.gdblib.arch.endian, extra
    )


# If passed an emulator, this will pass it to the DisassemblyAssistant
# which will single_step the emulator to determine the operand values before and after the instruction executes
def get_one_instruction(
    address, emu: pwndbg.emu.emulator.Emulator = None, enhance=True, from_cache=False, put_cache=False
) -> PwndbgInstruction:
    if from_cache:
        cached = computed_instruction_cache[address]
        if cached is not None:
            return cached

    if pwndbg.gdblib.arch.current not in CapstoneArch:
        return make_simple_instruction(address)

    md = get_disassembler(address)
    size = VariableInstructionSizeMax.get(pwndbg.gdblib.arch.current, 4)
    data = pwndbg.gdblib.memory.read(address, size, partial=True)
    for ins in md.disasm(bytes(data), address, 1):
        pwn_ins = PwndbgInstruction(ins)

        if enhance:
            pwndbg.disasm.arch.DisassemblyAssistant.enhance(pwn_ins, emu)

        if put_cache:
            computed_instruction_cache[address] = pwn_ins

        return pwn_ins

    # Make linter happy. This shouldn't occur as md.disasm would crash first.
    return None


# Return None on failure to fetch an instruction
def one(
    address=None, emu: pwndbg.emu.emulator.Emulator = None, enhance=True, from_cache=False, put_cache=False
) -> PwndbgInstruction | None:
    if address is None:
        address = pwndbg.gdblib.regs.pc

    if not pwndbg.gdblib.memory.peek(address):
        return None

    # A for loop in case this returns an empty list
    for insn in get(address, 1, emu, enhance=enhance, from_cache=from_cache, put_cache=put_cache):
        backward_cache[insn.next] = insn.address
        return insn

    return None


# Get one instruction without enhancement
def one_raw(address=None) -> PwndbgInstruction | None:
    if address is None:
        address = pwndbg.gdblib.regs.pc

    if not pwndbg.gdblib.memory.peek(address):
        return None

    return get_one_instruction(address, enhance=False)


def get(
    address, instructions=1, emu: pwndbg.emu.emulator.Emulator = None, enhance=True, from_cache=False, put_cache=False
) -> list[PwndbgInstruction]:
    address = int(address)

    # Dont disassemble if there's no memory
    if not pwndbg.gdblib.memory.peek(address):
        return []

    retval: list[PwndbgInstruction] = []
    for _ in range(instructions):
        i = get_one_instruction(address, emu, enhance=enhance, from_cache=from_cache, put_cache=put_cache)
        if i is None:
            break
        address = i.next
        retval.append(i)

    return retval


# These instruction types should not be emulated through, either
# because they cannot be emulated without interfering (syscall, etc.)
# or because they may take a long time (call, etc.), or because they
# change privilege levels.
DO_NOT_EMULATE = {
    capstone.CS_GRP_CALL,
    capstone.CS_GRP_INT,
    capstone.CS_GRP_INVALID,
    capstone.CS_GRP_IRET,
    # Note that we explicitly do not include the PRIVILEGE category, since
    # we may be in kernel code, and privileged instructions are just fine
    # in that case.
    # capstone.CS_GRP_PRIVILEGE,
}


def can_run_first_emulate() -> bool:
    """
    Disable the emulate config variable if we don't have enough memory to use it
    See https://github.com/pwndbg/pwndbg/issues/1534
    And https://github.com/unicorn-engine/unicorn/pull/1743
    """
    global first_time_emulate
    if not first_time_emulate:
        return True
    first_time_emulate = False

    try:
        from mmap import mmap, MAP_ANON, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE  # isort:skip

        mm = mmap(  # novm
            -1, 1024 * 1024 * 1024, MAP_PRIVATE | MAP_ANON, PROT_WRITE | PROT_READ | PROT_EXEC
        )
        mm.close()
    except OSError:
        print(
            message.error(
                "Disabling the emulation via Unicorn Engine that is used for computing branches"
                " as there isn't enough memory (1GB) to use it (since mmap(1G, RWX) failed). See also:\n"
                "* https://github.com/pwndbg/pwndbg/issues/1534\n"
                "* https://github.com/unicorn-engine/unicorn/pull/1743\n"
                "Either free your memory or explicitly set `set emulate off` in your Pwndbg config"
            )
        )
        gdb.execute("set emulate off", to_string=True)
        return False

    return True


first_time_emulate = True


def near(address, instructions=1, emulate=False, show_prev_insns=True) -> list[PwndbgInstruction]:
    """
    Disasms instructions near given `address`. Passing `emulate` makes use of
    unicorn engine to emulate instructions to predict branches that will be taken.
    `show_prev_insns` makes this show previously cached instructions
    (this is mostly used by context's disasm display, so user see what was previously)
    """

    pc = pwndbg.gdblib.regs.pc

    # Some architecture aren't emulated yet
    if not pwndbg.emu or pwndbg.gdblib.arch.current not in pwndbg.emu.emulator.arch_to_UC:
        emulate = False

    emu: pwndbg.emu.emulator.Emulator = None

    # Emulate if program pc is at the current instruction - can't emulate at arbitrary places, because we need current
    # processor state to instantiate the emulator.
    if address == pc and emulate and (not first_time_emulate or can_run_first_emulate()):
        emu = pwndbg.emu.emulator.Emulator()

    # Start at the current instruction using emulating if available.
    current = one(address, emu, put_cache=True)

    if DEBUG_ENHANCEMENT:
        if None in emu.last_single_step_result:
            print("Emulator failed at first step")

    if current is None:
        return []

    insns: list[PwndbgInstruction] = []

    # Get previously executed instructions from the cache.
    if DEBUG_ENHANCEMENT:
        print("CACHE START -------------------")
    if show_prev_insns:
        cached = backward_cache[current.address]
        insn = one(cached, from_cache=True) if cached else None
        while insn is not None and len(insns) < instructions:
            if DEBUG_ENHANCEMENT:
                print(f"Got instruction from cache, addr={cached:#x}")
            insns.append(insn)
            cached = backward_cache[insn.address]
            insn = one(cached, from_cache=True) if cached else None
        insns.reverse()

    insns.append(current)
    if DEBUG_ENHANCEMENT:
        print("END CACHE -------------------")

    # At this point, we've already added everything *BEFORE* the requested address,
    # and the instruction at 'address'.
    # Now, continue forwards.

    insn = current
    total_instructions = 1 + (2 * instructions)

    while insn and len(insns) < total_instructions:
        # Address to disassemble & emulate
        target = insn.next
        
        # Disable emulation if necessary
        if emulate and set(insn.groups) & DO_NOT_EMULATE:
            emulate = False
            emu = None

            if DEBUG_ENHANCEMENT:
                print("Turned off enhancement, not emulating certain type of instruction")

        # If using emulation and it's still enabled, use it to determine the next instruction executed
        if emu:
            if None not in emu.last_single_step_result:
                # Next instruction to be executed is where the emulator is
                target = emu.pc
            else:
                # If it failed, was not able to run the instruction
                emu = None

        insn = one(target, emu, put_cache=True)

        # TODO: Get rid of this check
        if emu and None not in emu.last_single_step_result:
            assert emu.last_pc == target

        if insn:
            insns.append(insn)

    # Remove repeated instructions at the end of disassembly.
    # Always ensure we display the current and *next* instruction,
    # but any repeats after that are removed.
    #
    # This helps with infinite loops and RET sleds.
    while insns and len(insns) > 2 and insns[-3].address == insns[-2].address == insns[-1].address:
        del insns[-1]

    return insns
