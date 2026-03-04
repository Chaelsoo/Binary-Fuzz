"""
Tests for kfuzz.engine.executor.

Compiles minimal test binaries at test time so the suite is not coupled to the
target/ programs. Run an integration smoke-test against any binary with:

    python tests/test_executor.py <binary_path>
"""

import os
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kfuzz.engine.executor import ExecResult, Executor


# ── helpers ──────────────────────────────────────────────────────────────────

def _compile(src: str, flags: list[str] | None = None) -> str:
    """Write C source to a temp file, compile it, return path to binary."""
    flags = flags or []
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w") as f:
        f.write(src)
        src_path = f.name

    out = src_path.replace(".c", "")
    subprocess.check_call(["gcc", src_path, "-o", out] + flags, stderr=subprocess.DEVNULL)
    os.unlink(src_path)
    return out


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def normal_binary():
    path = _compile('int main(void){return 0;}')
    yield path
    os.unlink(path)


@pytest.fixture(scope="session")
def crash_binary():
    src = """
#include <string.h>
int main(void){
    char buf[8];
    char big[200];
    memset(big, 'A', sizeof(big));
    strcpy(buf, big);
    return 0;
}
"""
    path = _compile(src, ["-fno-stack-protector", "-no-pie"])
    yield path
    os.unlink(path)


@pytest.fixture(scope="session")
def hang_binary():
    path = _compile('int main(void){while(1);}')
    yield path
    os.unlink(path)


# ── tests ─────────────────────────────────────────────────────────────────────

def test_normal_exit(normal_binary):
    exe = Executor(target=normal_binary, timeout_ms=500)
    r = exe.run(b"anything")
    assert r.result == ExecResult.NORMAL
    assert r.signal_num is None


def test_crash_detected(crash_binary):
    exe = Executor(target=crash_binary, timeout_ms=500)
    r = exe.run(b"trigger")
    assert r.result == ExecResult.CRASH
    assert r.signal_name == "SIGSEGV"
    assert r.signal_num == 11


def test_hang_detected(hang_binary):
    exe = Executor(target=hang_binary, timeout_ms=300)
    r = exe.run(b"")
    assert r.result == ExecResult.HANG
    assert r.signal_num is None


def test_exec_time_measured(normal_binary):
    exe = Executor(target=normal_binary, timeout_ms=500)
    r = exe.run(b"")
    assert r.exec_time_ms > 0


def test_missing_binary_raises():
    exe = Executor(target="/nonexistent/binary", timeout_ms=500)
    with pytest.raises(RuntimeError, match="not found"):
        exe.run(b"")


# ── integration smoke-test (run with: python tests/test_executor.py <binary>) ─

def _smoke(binary: str):
    exe = Executor(target=binary, timeout_ms=1000)

    r = exe.run(b"hello")
    print(f"  short input  -> {r.result.value}  ({r.exec_time_ms:.1f}ms)")

    r = exe.run(b"A" * 300)
    print(f"  300 x 'A'   -> {r.result.value}" + (f"  signal={r.signal_name}" if r.signal_num else "") + f"  ({r.exec_time_ms:.1f}ms)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: python {sys.argv[0]} <binary>")
        sys.exit(1)
    target = sys.argv[1]
    print(f"Smoke-testing Executor against: {target}")
    _smoke(target)
