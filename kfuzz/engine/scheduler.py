import hashlib
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Seed:
    id:           int
    data:         bytes
    filename:     str      = ""
    new_edges:    int      = 0
    energy:       float    = 1.0
    fuzz_count:   int      = 0
    exec_time_ms: float    = 0.0
    depth:        int      = 0
    source:       str      = "initial"

    def content_hash(self) -> str:
        return hashlib.sha1(self.data).hexdigest()


class SeedQueue:
    def __init__(self):
        self._seeds:   list[Seed] = []
        self._seen:    set[str]   = set()   # content hashes
        self._counter: int        = 0       # total picks (for round-robin)
        self._rr_idx:  int        = 0       # round-robin cursor

    @property
    def size(self) -> int:
        return len(self._seeds)

    def seeds(self) -> list[Seed]:
        return list(self._seeds)

    def load_seeds_from_dir(self, path: str):
        p = Path(path)
        if not p.is_dir():
            raise FileNotFoundError(f"Seed directory not found: {path}")
        for f in sorted(p.iterdir()):
            if f.is_file():
                data = f.read_bytes()
                self.add_seed(data, filename=f.name, source="initial")

    def add_seed(
        self,
        data:         bytes,
        new_edges:    int   = 0,
        exec_time_ms: float = 0.0,
        depth:        int   = 0,
        source:       str   = "mutation",
        filename:     str   = "",
    ) -> Optional[Seed]:
        h = hashlib.sha1(data).hexdigest()
        if h in self._seen:
            return None
        self._seen.add(h)

        seed_id = len(self._seeds)
        if not filename:
            filename = f"id_{seed_id:06d}"

        seed = Seed(
            id=seed_id,
            data=data,
            filename=filename,
            new_edges=new_edges,
            energy=self._initial_energy(data, new_edges, exec_time_ms),
            exec_time_ms=exec_time_ms,
            depth=depth,
            source=source,
        )
        self._seeds.append(seed)
        return seed

    def next_seed(self) -> Optional[Seed]:
        if not self._seeds:
            return None

        self._counter += 1

        # Every 10th pick: round-robin so low-energy seeds don't starve
        if self._counter % 10 == 0:
            seed = self._seeds[self._rr_idx % len(self._seeds)]
            self._rr_idx += 1
            seed.fuzz_count += 1
            return seed

        # Weighted random selection by energy
        total = sum(s.energy for s in self._seeds)
        r = random.uniform(0, total)
        cumulative = 0.0
        for seed in self._seeds:
            cumulative += seed.energy
            if r <= cumulative:
                seed.fuzz_count += 1
                return seed

        # Fallback (floating point edge case)
        self._seeds[-1].fuzz_count += 1
        return self._seeds[-1]

    def boost_energy(self, seed: Seed, new_edges: int = 1):
        seed.energy += new_edges * 2.0
        # Soft cap to avoid one dominant seed
        seed.energy = min(seed.energy, 100.0)

    def save_queue(self, path: str):
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        for seed in self._seeds:
            out = p / seed.filename
            out.write_bytes(seed.data)

    def _initial_energy(self, data: bytes, new_edges: int, exec_time_ms: float) -> float:
        energy = 1.0 + new_edges * 2.0

        # Smaller inputs get a modest boost — they're cheaper to mutate
        if len(data) < 64:
            energy *= 1.5
        elif len(data) > 4096:
            energy *= 0.75

        # Faster execution → more iterations per second
        if exec_time_ms > 0 and exec_time_ms < 100:
            energy *= 1.2

        return min(energy, 100.0)
