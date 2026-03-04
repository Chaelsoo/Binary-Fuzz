import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kfuzz.engine.scheduler import Seed, SeedQueue


def test_add_seed_returns_seed():
    q = SeedQueue()
    s = q.add_seed(b"AAAA", new_edges=5)
    assert isinstance(s, Seed)
    assert s.data == b"AAAA"
    assert s.new_edges == 5


def test_size_reflects_additions():
    q = SeedQueue()
    q.add_seed(b"AAAA", new_edges=5)
    q.add_seed(b"BBBB", new_edges=1)
    assert q.size == 2


def test_duplicate_ignored():
    q = SeedQueue()
    q.add_seed(b"AAAA", new_edges=5)
    result = q.add_seed(b"AAAA", new_edges=5)
    assert result is None
    assert q.size == 1


def test_next_seed_returns_seed():
    q = SeedQueue()
    q.add_seed(b"AAAA")
    s = q.next_seed()
    assert s is not None
    assert s.data == b"AAAA"


def test_next_seed_empty_queue():
    q = SeedQueue()
    assert q.next_seed() is None


def test_fuzz_count_increments():
    q = SeedQueue()
    q.add_seed(b"AAAA")
    s = q.next_seed()
    assert s.fuzz_count == 1
    q.next_seed()
    # Either the same seed or a different one — total fuzz_counts should grow
    total = sum(s.fuzz_count for s in q.seeds())
    assert total >= 2


def test_high_energy_seed_selected_more_often():
    """Seed with 10x the energy should win the majority of weighted picks."""
    q = SeedQueue()
    lo = q.add_seed(b"LOW",  new_edges=0)
    hi = q.add_seed(b"HIGH", new_edges=50)

    lo.energy = 1.0
    hi.energy = 50.0

    counts = {b"LOW": 0, b"HIGH": 0}
    for _ in range(500):
        # Skip every 10th (round-robin) pick to isolate weighted behaviour
        q._counter = 1  # prevent round-robin kicks in
        s = q.next_seed()
        counts[s.data] += 1
        s.fuzz_count -= 1  # undo so we're testing selection not side effects

    assert counts[b"HIGH"] > counts[b"LOW"] * 3


def test_round_robin_prevents_starvation():
    """Every 10th pick must use round-robin, so even zero-energy seeds get runs."""
    q = SeedQueue()
    q.add_seed(b"A")
    q.add_seed(b"B")
    q.add_seed(b"C")

    # Force all picks to be round-robin by resetting counter to multiples of 10
    for s in q.seeds():
        s.energy = 0.001  # near-zero energy

    seen = set()
    for i in range(30):
        q._counter = i * 10  # every pick triggers round-robin
        s = q.next_seed()
        seen.add(s.data)

    assert len(seen) == 3  # all 3 seeds must have been picked


def test_boost_energy_increases_energy():
    q = SeedQueue()
    s = q.add_seed(b"AAAA")
    before = s.energy
    q.boost_energy(s, new_edges=5)
    assert s.energy > before


def test_boost_energy_capped_at_100():
    q = SeedQueue()
    s = q.add_seed(b"AAAA")
    s.energy = 99.0
    q.boost_energy(s, new_edges=100)
    assert s.energy == 100.0


def test_load_seeds_from_dir():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "seed_a.bin").write_bytes(b"hello")
        Path(d, "seed_b.bin").write_bytes(b"world")

        q = SeedQueue()
        q.load_seeds_from_dir(d)
        assert q.size == 2
        datas = {s.data for s in q.seeds()}
        assert b"hello" in datas
        assert b"world" in datas


def test_load_seeds_missing_dir_raises():
    q = SeedQueue()
    with pytest.raises(FileNotFoundError):
        q.load_seeds_from_dir("/nonexistent/path/seeds")


def test_save_queue_writes_files():
    with tempfile.TemporaryDirectory() as d:
        q = SeedQueue()
        q.add_seed(b"data1", filename="s1")
        q.add_seed(b"data2", filename="s2")
        q.save_queue(d)
        assert (Path(d) / "s1").read_bytes() == b"data1"
        assert (Path(d) / "s2").read_bytes() == b"data2"
