import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kfuzz.engine.coverage import MAP_SIZE, CoverageBitmap


@pytest.fixture
def bm():
    b = CoverageBitmap()
    b.setup()
    yield b
    b.cleanup()


def test_reset_zeroes_bitmap(bm):
    bm.bitmap[42] = 99
    bm.reset()
    assert all(v == 0 for v in bm.read_raw())


def test_read_raw_length(bm):
    assert len(bm.read_raw()) == MAP_SIZE


def test_manual_write_visible_in_read(bm):
    bm.reset()
    bm.bitmap[100] = 1
    bm.bitmap[200] = 3
    trace = bm.read_raw()
    assert trace[100] == 1
    assert trace[200] == 3


def test_new_coverage_detected(bm):
    bm.reset()
    bm.bitmap[100] = 1
    bm.bitmap[200] = 3
    trace = bm.read_raw()
    has_new, count = bm.has_new_coverage(trace)
    assert has_new is True
    assert count == 2


def test_same_trace_not_new(bm):
    bm.reset()
    bm.bitmap[100] = 1
    bm.bitmap[200] = 3
    trace = bm.read_raw()
    bm.has_new_coverage(trace)  # first — marks as seen

    bm.reset()
    bm.bitmap[100] = 1
    bm.bitmap[200] = 3
    trace = bm.read_raw()
    has_new, count = bm.has_new_coverage(trace)
    assert has_new is False
    assert count == 0


def test_higher_hit_count_bucket_is_new(bm):
    """Jumping from bucket 1 (hit=1) to bucket 2 (hit=2) counts as new coverage."""
    bm.reset()
    bm.bitmap[50] = 1  # bucket → 1
    bm.has_new_coverage(bm.read_raw())

    bm.reset()
    bm.bitmap[50] = 2  # bucket → 2 (higher than 1)
    has_new, count = bm.has_new_coverage(bm.read_raw())
    assert has_new is True
    assert count == 1


def test_bucketing_same_bucket_not_new(bm):
    """Values 4 and 7 both map to bucket 8 — the second should not be new."""
    bm.reset()
    bm.bitmap[77] = 4  # bucket → 8
    bm.has_new_coverage(bm.read_raw())

    bm.reset()
    bm.bitmap[77] = 7  # bucket → 8 still
    has_new, count = bm.has_new_coverage(bm.read_raw())
    assert has_new is False


def test_empty_trace_not_new(bm):
    bm.reset()
    trace = bm.read_raw()
    has_new, count = bm.has_new_coverage(trace)
    assert has_new is False
    assert count == 0


def test_shm_id_set(bm):
    assert bm.shm_id >= 0


def test_env_contains_shm_id(bm):
    e = bm.env()
    assert "__AFL_SHM_ID" in e
    assert e["__AFL_SHM_ID"] == str(bm.shm_id)


def test_cleanup_does_not_raise():
    b = CoverageBitmap()
    b.setup()
    b.cleanup()
    b.cleanup()  # second call should be a no-op, not an error
