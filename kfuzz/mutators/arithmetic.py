import random
import struct

from .base import Mutator

INTERESTING_8  = [0, 1, 0x7F, 0x80, 0xFF]
INTERESTING_16 = [0, 1, 0x7FFF, 0x8000, 0xFFFF]
INTERESTING_32 = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


class ArithmeticMutator(Mutator):
    @property
    def name(self) -> str:
        return "arithmetic"

    def mutate(self, data: bytes, max_mutations: int = 16) -> list[bytes]:
        if not data:
            return [data] * max_mutations

        results = []
        ops = (
            self._add_sub_byte,
            self._interesting_byte,
            self._interesting_16le,
            self._interesting_16be,
            self._interesting_32le,
            self._interesting_32be,
        )
        for _ in range(max_mutations):
            op = random.choice(ops)
            results.append(op(bytearray(data)))
        return results

    # ── ops ───────────────────────────────────────────────────────────────────

    def _add_sub_byte(self, buf: bytearray) -> bytes:
        pos = random.randrange(len(buf))
        delta = random.randint(1, 35) * random.choice([-1, 1])
        buf[pos] = (buf[pos] + delta) & 0xFF
        return bytes(buf)

    def _interesting_byte(self, buf: bytearray) -> bytes:
        pos = random.randrange(len(buf))
        buf[pos] = random.choice(INTERESTING_8)
        return bytes(buf)

    def _interesting_16le(self, buf: bytearray) -> bytes:
        if len(buf) < 2:
            return self._interesting_byte(buf)
        pos = random.randrange(len(buf) - 1)
        val = random.choice(INTERESTING_16)
        struct.pack_into("<H", buf, pos, val)
        return bytes(buf)

    def _interesting_16be(self, buf: bytearray) -> bytes:
        if len(buf) < 2:
            return self._interesting_byte(buf)
        pos = random.randrange(len(buf) - 1)
        val = random.choice(INTERESTING_16)
        struct.pack_into(">H", buf, pos, val)
        return bytes(buf)

    def _interesting_32le(self, buf: bytearray) -> bytes:
        if len(buf) < 4:
            return self._interesting_byte(buf)
        pos = random.randrange(len(buf) - 3)
        val = random.choice(INTERESTING_32)
        struct.pack_into("<I", buf, pos, val)
        return bytes(buf)

    def _interesting_32be(self, buf: bytearray) -> bytes:
        if len(buf) < 4:
            return self._interesting_byte(buf)
        pos = random.randrange(len(buf) - 3)
        val = random.choice(INTERESTING_32)
        struct.pack_into(">I", buf, pos, val)
        return bytes(buf)
