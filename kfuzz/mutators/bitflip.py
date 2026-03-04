import random
import struct

from .base import Mutator


class BitFlipMutator(Mutator):
    @property
    def name(self) -> str:
        return "bitflip"

    def mutate(self, data: bytes, max_mutations: int = 16) -> list[bytes]:
        if not data:
            return [data] * max_mutations

        results = []
        ops = (
            self._flip_bit,
            self._flip_bits2,
            self._flip_bits4,
            self._flip_byte,
            self._flip_bytes2,
            self._flip_bytes4,
            self._rand_byte,
        )
        for _ in range(max_mutations):
            op = random.choice(ops)
            results.append(op(bytearray(data)))
        return results

    # ── individual ops ────────────────────────────────────────────────────────

    def _flip_bit(self, buf: bytearray) -> bytes:
        pos = random.randrange(len(buf))
        bit = 1 << random.randrange(8)
        buf[pos] ^= bit
        return bytes(buf)

    def _flip_bits2(self, buf: bytearray) -> bytes:
        pos = random.randrange(len(buf))
        buf[pos] ^= 0b11 << random.randrange(7)
        return bytes(buf)

    def _flip_bits4(self, buf: bytearray) -> bytes:
        pos = random.randrange(len(buf))
        buf[pos] ^= 0b1111 << random.randrange(5)
        return bytes(buf)

    def _flip_byte(self, buf: bytearray) -> bytes:
        pos = random.randrange(len(buf))
        buf[pos] ^= 0xFF
        return bytes(buf)

    def _flip_bytes2(self, buf: bytearray) -> bytes:
        if len(buf) < 2:
            return self._flip_byte(buf)
        pos = random.randrange(len(buf) - 1)
        buf[pos]     ^= 0xFF
        buf[pos + 1] ^= 0xFF
        return bytes(buf)

    def _flip_bytes4(self, buf: bytearray) -> bytes:
        if len(buf) < 4:
            return self._flip_byte(buf)
        pos = random.randrange(len(buf) - 3)
        for i in range(4):
            buf[pos + i] ^= 0xFF
        return bytes(buf)

    def _rand_byte(self, buf: bytearray) -> bytes:
        pos = random.randrange(len(buf))
        buf[pos] = random.randint(0, 255)
        return bytes(buf)
