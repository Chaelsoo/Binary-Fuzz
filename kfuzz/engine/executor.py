import os
import resource
import signal
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ExecResult(str, Enum):
    NORMAL = "NORMAL"
    CRASH  = "CRASH"
    HANG   = "HANG"


CRASH_SIGNALS = {
    signal.SIGSEGV,
    signal.SIGABRT,
    signal.SIGFPE,
    signal.SIGILL,
    signal.SIGBUS,
}

MEMORY_LIMIT = 256 * 1024 * 1024  # 256 MB


@dataclass
class RunResult:
    result:      ExecResult
    signal_num:  Optional[int] = None
    signal_name: Optional[str] = None
    exec_time_ms: float = 0.0
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)


def _set_limits():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))


class Executor:
    def __init__(self, target: str, timeout_ms: int = 1000, qemu_mode: bool = False):
        self.target      = os.path.abspath(target)
        self.timeout_ms  = timeout_ms
        self.qemu_mode   = qemu_mode
        self.timeout_sec = timeout_ms / 1000.0

    def _build_cmd(self) -> list:
        if self.qemu_mode:
            return ["afl-qemu-trace", self.target]
        return [self.target]

    def run(self, input_data: bytes, extra_env: dict | None = None) -> RunResult:
        cmd = self._build_cmd()
        start = time.monotonic()

        env = None
        if extra_env:
            env = os.environ.copy()
            env.update(extra_env)

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=_set_limits,
                env=env,
            )
            try:
                stdout, stderr = proc.communicate(input=input_data, timeout=self.timeout_sec)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                elapsed = (time.monotonic() - start) * 1000
                return RunResult(result=ExecResult.HANG, exec_time_ms=elapsed)

        except FileNotFoundError:
            raise RuntimeError(f"Target not found: {self.target}")

        elapsed = (time.monotonic() - start) * 1000
        rc = proc.returncode

        if rc >= 0:
            return RunResult(
                result=ExecResult.NORMAL,
                exec_time_ms=elapsed,
                stdout=stdout,
                stderr=stderr,
            )

        sig_num = -rc
        try:
            sig = signal.Signals(sig_num)
            sig_name = sig.name
        except ValueError:
            sig = None
            sig_name = f"SIG{sig_num}"

        result = ExecResult.CRASH if (sig in CRASH_SIGNALS) else ExecResult.NORMAL

        return RunResult(
            result=result,
            signal_num=sig_num,
            signal_name=sig_name,
            exec_time_ms=elapsed,
            stdout=stdout,
            stderr=stderr,
        )
