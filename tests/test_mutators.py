import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kfuzz.mutators.arithmetic import ArithmeticMutator
from kfuzz.mutators.bitflip import BitFlipMutator
from kfuzz.mutators.havoc import HavocMutator


SEED = b"AAAA"
N    = 32


# ── shared contract tests ─────────────────────────────────────────────────────

@pytest.mark.parametrize("mutator_cls", [BitFlipMutator, ArithmeticMutator, HavocMutator])
def test_returns_correct_count(mutator_cls):
    m = mutator_cls()
    results = m.mutate(SEED, max_mutations=N)
    assert len(results) == N


@pytest.mark.parametrize("mutator_cls", [BitFlipMutator, ArithmeticMutator, HavocMutator])
def test_all_bytes(mutator_cls):
    m = mutator_cls()
    results = m.mutate(SEED, max_mutations=N)
    assert all(isinstance(r, bytes) for r in results)


@pytest.mark.parametrize("mutator_cls", [BitFlipMutator, ArithmeticMutator, HavocMutator])
def test_produces_diversity(mutator_cls):
    m = mutator_cls()
    results = m.mutate(SEED, max_mutations=N)
    assert any(r != SEED for r in results), "all outputs identical to seed"


@pytest.mark.parametrize("mutator_cls", [BitFlipMutator, ArithmeticMutator, HavocMutator])
def test_empty_seed(mutator_cls):
    m = mutator_cls()
    results = m.mutate(b"", max_mutations=4)
    assert len(results) == 4
    assert all(isinstance(r, bytes) for r in results)


# ── mutator-specific tests ────────────────────────────────────────────────────

def test_bitflip_single_bit_differs_by_one_bit():
    """Each individual flip should differ from the seed by exactly the bits that were flipped."""
    m = BitFlipMutator()
    # Run many times; at least some should differ by exactly 1 bit
    results = m.mutate(b"\x00" * 8, max_mutations=64)
    one_bit_diffs = [
        r for r in results
        if sum(bin(a ^ b).count("1") for a, b in zip(r, b"\x00" * 8)) == 1
    ]
    assert len(one_bit_diffs) > 0


def test_arithmetic_interesting_values_appear():
    m = ArithmeticMutator()
    results = m.mutate(b"\x42" * 8, max_mutations=200)
    all_bytes = set(b for r in results for b in r)
    # 0x00 and 0xFF are both interesting values that should appear over 200 runs
    assert 0x00 in all_bytes or 0xFF in all_bytes


def test_havoc_length_varies():
    """Havoc should produce outputs of varying lengths (insert/delete/truncate/extend)."""
    m = HavocMutator()
    results = m.mutate(b"AAAABBBBCCCC", max_mutations=64)
    lengths = {len(r) for r in results}
    assert len(lengths) > 1, "havoc produced identical lengths for all mutations"


def test_havoc_format_probes_can_appear():
    m = HavocMutator()
    results = m.mutate(b"hello", max_mutations=512)
    found = any(b"%s" in r or b"%n" in r or b"%x" in r for r in results)
    assert found, "format string probes never appeared in 512 havoc mutations"
