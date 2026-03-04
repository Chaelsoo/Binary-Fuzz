# KFuzz

Coverage-guided binary fuzzer built for CTF and black-box targets.

Uses AFL++ QEMU mode to instrument arbitrary ELF binaries at runtime, collects edge coverage via shared memory, and drives mutation based on what paths were discovered.

---

## How it works

KFuzz runs the target under `afl-qemu-trace`, which patches QEMU's userspace emulator to record every basic-block transition into a 65536-byte shared memory bitmap. The fuzzer owns that bitmap, reads it after each execution, and decides whether the input opened up new code paths.

```
┌─────────────┐     stdin      ┌──────────────────────┐
│   KFuzz     │ ─────────────► │  afl-qemu-trace       │
│  (Python)   │                │  (patched QEMU)       │
│             │ ◄────────────  │  instruments every    │
│  reads shm  │   shm bitmap   │  branch transition    │
└─────────────┘                └──────────────────────┘
```

**Coverage loop:**
1. Allocate a System V shared memory segment, pass its ID via `__AFL_SHM_ID`
2. QEMU reads the env var on startup, maps the same segment, writes edge counters into it
3. After each run, read the bitmap and compare against historical maximums using hit-count bucketing (1, 2, 4, 8, 16, 32, 64, 128)
4. If any edge crossed into a new bucket, the input is "interesting" — save it, boost its energy, mutate from it next

**Dual execution for crash detection:**
QEMU's virtual memory layout can swallow certain crashes (heap overflows that don't hit a guard page in QEMU's address space). When QEMU returns exit code 0, KFuzz re-runs the same input natively to confirm whether a crash actually occurred. Coverage is still collected from the QEMU run.

---

## Features

- QEMU binary-only instrumentation — works on any x86-64 ELF without source
- Edge coverage with hit-count bucketing (AFL++ compatible bitmap format)
- Weighted seed scheduling with round-robin anti-starvation
- Three mutators: bit/byte flip, arithmetic, havoc (stacked random ops)
- Crash deduplication by stack hash (SHA1 of top 5 GDB frames)
- Crash classification: Stack BOF, Heap Corruption, Format String, Null Deref, Stack Canary, Assertion, Div Zero
- Dangerous function scanner via `nm -D` + `strings`
- JSON and text output for triage results

---

## Installation

**Requirements:** Python 3.10+, GDB, `afl-qemu-trace` in PATH

### 1. Build afl-qemu-trace

The Kali `afl++` package does not ship `afl-qemu-trace`. Build it from source (use a path with no spaces):

```bash
cd /tmp
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo apt install meson ninja-build -y
cd qemu_mode && ./build_qemu_support.sh
sudo cp /tmp/AFLplusplus/afl-qemu-trace /usr/local/bin/
```

### 2. Install KFuzz

```bash
pip install -e .
```

### 3. Verify

```bash
kfuzz -v
which afl-qemu-trace
```

---

## Usage

### Fuzz a binary

```bash
kfuzz fuzz -t ./target -i seeds/ -o findings/
```

Add `--qemu` for uninstrumented binaries:

```bash
kfuzz fuzz --qemu -t ./target -i seeds/ -o findings/
```

Options:

| Flag | Default | Description |
|---|---|---|
| `-t` | required | Path to target binary |
| `-i` | required | Seed input directory |
| `-o` | required | Output directory (crashes/, hangs/, queue/) |
| `--qemu` | off | Enable QEMU binary-only instrumentation |
| `--timeout` | 1000ms | Per-execution timeout |
| `--max-time` | unlimited | Total fuzzing time in seconds |
| `--max-execs` | unlimited | Stop after N executions |

### Scan for dangerous functions

```bash
kfuzz scan ./target
```

Runs `nm -D` and `strings` to detect dangerous libc functions (strcpy, gets, printf used as sink, etc.) and reports risk level per finding.

### Triage crashes

```bash
kfuzz triage -t ./target -c findings/crashes/
```

Runs each crash file through GDB, extracts registers and backtrace, classifies the bug type, deduplicates by stack hash, and prints a ranked report.

JSON output:

```bash
kfuzz triage -t ./target -c findings/crashes/ --format json
```

---

## Output structure

```
findings/
├── crashes/    # inputs that caused a crash signal (SIGSEGV, SIGABRT, etc.)
├── hangs/      # inputs that exceeded the timeout
└── queue/      # inputs that discovered new edges, saved for future mutation
```

Each file in `crashes/` is the raw bytes that triggered that crash. Replay any crash:

```bash
cat findings/crashes/id_000001_SIGSEGV | ./target
```

---

## Seeds

Place at least one seed file in your input directory. Seeds are raw binary files fed to the target via stdin. Better seeds = faster coverage, but KFuzz can navigate from generic inputs using coverage guidance alone.

Example: starting from `hello` (5 bytes), KFuzz found the crash in `integer_overflow` (which requires a specific 4-byte magic header + crafted length field) in under 35 seconds.

---

## Test targets

Four vulnerable C binaries are included in `targets/` for testing:

| Target | Bug | Trigger |
|---|---|---|
| `stack_bof` | Stack buffer overflow via `strcpy` | Any input > 64 bytes |
| `heap_uaf` | Double-free via command sequence | Input containing `AFR` |
| `format_string` | `printf(user_input)` | Input containing `%n` |
| `integer_overflow` | `uint16_t` wrap bypasses size check | Magic header `FU` + crafted length |

---

## Project structure

```
kfuzz/
├── cli.py                  # argparse entry point (fuzz, scan, triage)
├── config.py               # FuzzerConfig dataclass
├── engine/
│   ├── executor.py         # subprocess runner, QEMU wrapper, dual crash detection
│   ├── coverage.py         # System V shm bitmap, bucketing, virgin map
│   ├── scheduler.py        # Seed dataclass, weighted queue, energy boosting
│   └── fuzzer.py           # Main loop: dry_run, mutation, crash/hang saving
├── mutators/
│   ├── base.py             # ABC
│   ├── bitflip.py          # 1/2/4-bit and 1/2/4-byte flips, random byte
│   ├── arithmetic.py       # add/sub ±35, interesting boundary values
│   └── havoc.py            # stacked random ops (overwrite, insert, delete, etc.)
└── triage/
    ├── dangerous_functions.py  # nm -D + strings scanner
    └── crash_analyzer.py       # GDB batch triage, classification, dedup
```
