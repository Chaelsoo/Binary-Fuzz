import random

from .base import Mutator

FORMAT_STRING_PROBES = [b"%s", b"%n", b"%x", b"%p", b"%%"]


class HavocMutator(Mutator):
    @property
    def name(self) -> str:
        return "havoc"

    def mutate(self, data: bytes, max_mutations: int = 16) -> list[bytes]:
        results = []
        for _ in range(max_mutations):
            buf = bytearray(data) if data else bytearray(b"\x00")
            stacked = random.randint(1, 16)
            for _ in range(stacked):
                buf = self._apply_one(buf)
            results.append(bytes(buf))
        return results

    def _apply_one(self, buf: bytearray) -> bytearray:
        if not buf:
            return bytearray(b"\x00")

        op = random.randrange(9)

        if op == 0:  # overwrite random byte
            buf[random.randrange(len(buf))] = random.randint(0, 255)

        elif op == 1:  # insert random byte
            pos = random.randrange(len(buf) + 1)
            buf.insert(pos, random.randint(0, 255))

        elif op == 2:  # delete random byte
            if len(buf) > 1:
                del buf[random.randrange(len(buf))]

        elif op == 3:  # copy chunk to random position
            if len(buf) >= 2:
                src  = random.randrange(len(buf))
                size = random.randint(1, min(32, len(buf) - src))
                dst  = random.randrange(len(buf))
                chunk = buf[src:src + size]
                buf[dst:dst + size] = chunk

        elif op == 4:  # fill chunk with a single byte
            if len(buf) >= 2:
                pos  = random.randrange(len(buf))
                size = random.randint(1, min(32, len(buf) - pos))
                fill = random.randint(0, 255)
                buf[pos:pos + size] = bytes([fill] * size)

        elif op == 5:  # insert format string probe
            probe = random.choice(FORMAT_STRING_PROBES)
            pos   = random.randrange(len(buf) + 1)
            buf[pos:pos] = probe

        elif op == 6:  # truncate
            if len(buf) > 1:
                new_len = random.randint(1, len(buf))
                del buf[new_len:]

        elif op == 7:  # extend with random bytes
            extra = random.randint(1, 32)
            buf.extend(random.randint(0, 255) for _ in range(extra))

        elif op == 8:  # overwrite with interesting value
            pos = random.randrange(len(buf))
            buf[pos] = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFF])

        return buf
