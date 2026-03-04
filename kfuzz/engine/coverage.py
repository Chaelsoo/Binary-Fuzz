import ctypes
import ctypes.util
import os
from typing import Tuple

MAP_SIZE    = 65536
IPC_PRIVATE = 0
IPC_CREAT   = 0o1000
IPC_RMID    = 0

# AFL++ QEMU reads this env var to find the shared memory segment
AFL_SHM_ENV_VAR = "__AFL_SHM_ID"

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.shmat.restype  = ctypes.c_void_p
_libc.shmdt.argtypes = [ctypes.c_void_p]

_SHMAT_FAILED = ctypes.c_void_p(-1).value  # (void*)-1


def _bucket(val: int) -> int:
    if val == 0:   return 0
    if val == 1:   return 1
    if val == 2:   return 2
    if val <= 3:   return 4
    if val <= 7:   return 8
    if val <= 15:  return 16
    if val <= 31:  return 32
    if val <= 127: return 64
    return 128


class CoverageBitmap:
    def __init__(self):
        self._shmid    = -1
        self._shm_ptr  = None
        self.bitmap    = None
        self._virgin   = bytearray(MAP_SIZE)  # max bucketed value seen per edge

    def setup(self):
        self._shmid = _libc.shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | 0o600)
        if self._shmid < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"shmget failed: {os.strerror(errno)}")

        ptr = _libc.shmat(self._shmid, None, 0)
        if ptr is None or ptr == _SHMAT_FAILED:
            errno = ctypes.get_errno()
            raise OSError(errno, f"shmat failed: {os.strerror(errno)}")

        self._shm_ptr = ptr
        self.bitmap   = (ctypes.c_uint8 * MAP_SIZE).from_address(ptr)
        self.reset()

    @property
    def shm_id(self) -> int:
        return self._shmid

    def env(self) -> dict:
        return {AFL_SHM_ENV_VAR: str(self._shmid)}

    def reset(self):
        ctypes.memset(self._shm_ptr, 0, MAP_SIZE)

    def read_raw(self) -> bytes:
        return bytes(self.bitmap)

    def has_new_coverage(self, trace: bytes) -> Tuple[bool, int]:
        new_count = 0
        for i, val in enumerate(trace):
            b = _bucket(val)
            if b > self._virgin[i]:
                self._virgin[i] = b
                new_count += 1
        return new_count > 0, new_count

    def cleanup(self):
        if self._shm_ptr is not None:
            _libc.shmdt(self._shm_ptr)
            self._shm_ptr = None
        if self._shmid >= 0:
            _libc.shmctl(self._shmid, IPC_RMID, None)
            self._shmid = -1
