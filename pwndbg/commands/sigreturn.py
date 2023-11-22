from __future__ import annotations

import argparse

import pwnlib.rop.srop

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.color.message
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.lib.regs import amd64 as amd64_regset

parser = argparse.ArgumentParser(description="Display the SigreturnFrame at the specific address")

parser.add_argument(
    "address", nargs="?", default=None, type=int, help="The address to read the frame from"
)

parser.add_argument(
    "-a",
    "--all",
    dest="display_all",
    action="store_true",
    default=False,
    help="Show all values in the frame in addition to common registers",
)

parser.add_argument(
    "-p",
    "--print",
    dest="print_address",
    action="store_true",
    default=False,
    help="Show addresses of frame values",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithArch(["x86-64"])
def sigreturn(address: int = None, display_all=False, print_address=False):
    address = pwndbg.gdblib.regs.sp if address is None else address

    arch_name = pwndbg.gdblib.arch.name
    if arch_name == "x86-64":
        sigreturn_x86_64(address, display_all, print_address)


SIGRETURN_FRAME_SIZE_x86_64 = 256

# Grab frame values from pwntools. Offsets are defined as the offset to stack pointer when syscall instruction is called
# Offsets and names are from "CONFIG_X86_64 struct rt_sigframe, Linux Kernel /arch/x86/include/asm/sigframe.h
SIGRETURN_FRAME_LAYOUT_x86_64 = sorted(
    [(-8, "&pretcode")] + list(pwnlib.rop.srop.SigreturnFrame(arch="amd64").registers.items())
)

# Core registers
SIGRETURN_REGISTERS_x86_64 = {
    *amd64_regset.gpr,
    amd64_regset.frame,
    amd64_regset.stack,
    amd64_regset.pc,
}


def print_value(string: str, address: int, print_address):
    addr = ""
    if print_address:
        addr = f"{M.get(address)}: "
    print(f"{addr}{string}")


def sigreturn_x86_64(address: int, display_all: bool, print_address: bool):
    ptr_size = pwndbg.gdblib.arch.ptrsize

    # Offset to the stack pointer where the frame values really begins. Start reading memory there.
    # Can be negative, 0, or positive
    frame_start_offset = SIGRETURN_FRAME_LAYOUT_x86_64[0][0]

    mem = pwndbg.gdblib.memory.read(address + frame_start_offset, SIGRETURN_FRAME_SIZE_x86_64)

    for stack_offset, reg in SIGRETURN_FRAME_LAYOUT_x86_64:
        # Subtract the offset of start of frame, to get the correct offset into "mem"
        mem_offset = stack_offset - frame_start_offset

        regname = C.register(reg.ljust(4).upper())
        value = pwndbg.gdblib.arch.unpack(mem[mem_offset : mem_offset + ptr_size])

        if reg in SIGRETURN_REGISTERS_x86_64:
            desc = pwndbg.chain.format(value)

            print_value(f"{regname} {desc}", address + stack_offset, print_address)

        elif reg == "eflags":
            reg_flags = pwndbg.gdblib.regs.flags["eflags"]
            desc = C.format_flags(value, reg_flags)

            print_value(f"{regname} {desc}", address + stack_offset, print_address)

        elif display_all:
            print_value(f"{reg} {M.get(value)}", address + stack_offset, print_address)
