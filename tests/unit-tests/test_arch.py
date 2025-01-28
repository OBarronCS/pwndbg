from __future__ import annotations

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES
from pwndbg.lib.arch import PWNLIB_ARCH_MAPPINGS
from pwndbg.lib.regs import reg_sets


def test_pwnlib_mappings_exist():
    arch_set: set[str] = set(PWNDBG_SUPPORTED_ARCHITECTURES)
    pwnlib_arch_mappings_set = set(PWNLIB_ARCH_MAPPINGS.keys())

    assert len(arch_set - pwnlib_arch_mappings_set) == 0


def test_reg_set_mappings_exist():
    arch_set: set[str] = set(PWNDBG_SUPPORTED_ARCHITECTURES)
    reg_sets_keys = set(reg_sets.keys())

    assert len(arch_set - reg_sets_keys) == 0
