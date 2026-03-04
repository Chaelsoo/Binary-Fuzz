import signal
import time
from pathlib import Path
from typing import Optional

from ..config import FuzzerConfig
from ..mutators.arithmetic import ArithmeticMutator
from ..mutators.bitflip import BitFlipMutator
from ..mutators.havoc import HavocMutator
from .coverage import CoverageBitmap
from .executor import ExecResult, Executor
from .scheduler import Seed, SeedQueue


class Fuzzer:
    def __init__(self, config: FuzzerConfig):
        self.config   = config
        self.executor = Executor(config.target, config.timeout_ms, config.qemu_mode)
        self.coverage = CoverageBitmap()
        self.queue    = SeedQueue()
        self.mutators = [BitFlipMutator(), ArithmeticMutator(), HavocMutator()]

        self.total_execs   = 0
        self.total_crashes = 0
        self.total_hangs   = 0
        self.unique_edges  = 0
        self.start_time    = 0.0
        self._last_status  = 0.0
        self._last_crash_id = 0
        self._last_hang_id  = 0
        self._crash_hashes: set[str] = set()

    def setup(self):
        self.coverage.setup()
        out = Path(self.config.output_dir)
        for sub in ("crashes", "hangs", "queue"):
            (out / sub).mkdir(parents=True, exist_ok=True)

    def load_seeds(self):
        self.queue.load_seeds_from_dir(self.config.input_dir)
        if self.queue.size == 0:
            raise RuntimeError(f"No seeds found in {self.config.input_dir}")
        print(f"[*] Loaded {self.queue.size} seed(s)")

    def dry_run(self):
        print("[*] Dry run: baselining coverage on initial seeds")
        for seed in self.queue.seeds():
            self.coverage.reset()
            result = self.executor.run(seed.data, extra_env=self.coverage.env())
            trace  = self.coverage.read_raw()
            has_new, count = self.coverage.has_new_coverage(trace)
            seed.exec_time_ms = result.exec_time_ms
            if has_new:
                self.unique_edges += count
            if result.result == ExecResult.CRASH:
                print(f"[!] Seed '{seed.filename}' already crashes — keeping it")
        print(f"[*] Baseline: {self.unique_edges} edges from {self.queue.size} seed(s)")

    def run(self):
        self.start_time   = time.monotonic()
        self._last_status = self.start_time

        print(f"[*] Fuzzing {self.config.target}")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            self._loop()
        except KeyboardInterrupt:
            pass
        finally:
            self._print_summary()
            self.coverage.cleanup()
            self.queue.save_queue(str(Path(self.config.output_dir) / "queue"))

    def _loop(self):
        while True:
            if self._time_limit_reached() or self._exec_limit_reached():
                break

            seed = self.queue.next_seed()
            if seed is None:
                break

            for mutator in self.mutators:
                mutations = mutator.mutate(seed.data, self.config.mutations_per_round)
                for mutated in mutations:
                    self._execute_one(mutated, parent=seed)
                    self.total_execs += 1

                    if self._time_limit_reached() or self._exec_limit_reached():
                        return

                    if time.monotonic() - self._last_status >= 5.0:
                        self._print_status()

    def _execute_one(self, data: bytes, parent: Seed):
        self.coverage.reset()
        result = self.executor.run(data, extra_env=self.coverage.env())
        trace  = self.coverage.read_raw()

        if result.result == ExecResult.CRASH:
            self._save_crash(data, result.signal_name or "UNKNOWN", parent)
            return

        if result.result == ExecResult.HANG:
            self._save_hang(data, parent)
            return

        has_new, count = self.coverage.has_new_coverage(trace)
        if has_new:
            self.unique_edges += count
            new_seed = self.queue.add_seed(
                data,
                new_edges=count,
                exec_time_ms=result.exec_time_ms,
                depth=parent.depth + 1,
                source=f"mutation:{parent.id}",
            )
            if new_seed:
                self.queue.boost_energy(parent, new_edges=count)
                print(
                    f"[+] New path: edges+{count:3d}  total={self.unique_edges:5d}"
                    f"  queue={self.queue.size:4d}  len={len(data)}"
                )

    def _save_crash(self, data: bytes, signal_name: str, parent: Seed):
        import hashlib
        h = hashlib.sha1(data).hexdigest()[:12]
        if h in self._crash_hashes:
            return
        self._crash_hashes.add(h)

        self.total_crashes += 1
        self._last_crash_id += 1
        name = f"id_{self._last_crash_id:06d}_{signal_name}"
        path = Path(self.config.output_dir) / "crashes" / name
        path.write_bytes(data)
        print(f"[!] CRASH  signal={signal_name:8s}  saved → crashes/{name}  (from seed {parent.id})")

    def _save_hang(self, data: bytes, parent: Seed):
        self.total_hangs += 1
        self._last_hang_id += 1
        name = f"id_{self._last_hang_id:06d}_HANG"
        path = Path(self.config.output_dir) / "hangs" / name
        path.write_bytes(data)
        print(f"[~] HANG   saved → hangs/{name}")

    def _print_status(self):
        elapsed = time.monotonic() - self.start_time
        speed   = self.total_execs / elapsed if elapsed > 0 else 0
        self._last_status = time.monotonic()
        print(
            f"[*] {elapsed:6.0f}s  execs={self.total_execs:7d}  speed={speed:6.0f}/s"
            f"  edges={self.unique_edges:5d}  queue={self.queue.size:4d}"
            f"  crashes={self.total_crashes}  hangs={self.total_hangs}"
        )

    def _print_summary(self):
        elapsed = time.monotonic() - self.start_time
        speed   = self.total_execs / elapsed if elapsed > 0 else 0
        print(f"\n{'─' * 50}")
        print(f"  Execs      : {self.total_execs:,}")
        print(f"  Speed      : {speed:,.0f} exec/s")
        print(f"  Uptime     : {elapsed:.1f}s")
        print(f"  Edges      : {self.unique_edges}")
        print(f"  Queue      : {self.queue.size} seeds")
        print(f"  Crashes    : {self.total_crashes}")
        print(f"  Hangs      : {self.total_hangs}")
        print(f"{'─' * 50}")

    def _time_limit_reached(self) -> bool:
        return (
            self.config.max_time > 0
            and (time.monotonic() - self.start_time) >= self.config.max_time
        )

    def _exec_limit_reached(self) -> bool:
        return self.config.max_execs > 0 and self.total_execs >= self.config.max_execs
