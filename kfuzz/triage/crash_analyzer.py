import hashlib
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CrashReport:
    crash_file:  str
    signal:      str
    crash_type:  str
    risk:        str
    fault_addr:  Optional[str]
    backtrace:   list[str]
    stack_hash:  str
    repro_cmd:   str
    gdb_output:  str = field(default="", repr=False)


_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _classify(signal: str, fault_addr: Optional[int], backtrace: str, regs: dict) -> tuple[str, str]:
    bt = backtrace.lower()

    if signal == "SIGFPE":
        return "Division by Zero", "LOW"

    if signal == "SIGILL":
        return "Illegal Instruction", "HIGH"

    if signal == "SIGBUS":
        return "Bus Error (misaligned access)", "MEDIUM"

    if signal == "SIGABRT":
        if "__stack_chk_fail" in bt:
            return "Stack Canary Detected", "MEDIUM"
        if "__assert_fail" in bt:
            return "Assertion Failure", "LOW"
        if any(w in bt for w in ("malloc", "free", "heap", "corrupted")):
            return "Heap Corruption", "HIGH"
        return "Abort", "MEDIUM"

    if signal == "SIGSEGV":
        if any(w in bt for w in ("malloc", "free", "heap")):
            return "Heap Corruption", "HIGH"
        if any(w in bt for w in ("printf", "fprintf", "vprintf", "_io_")):
            return "Format String", "HIGH"

        rip_val = _reg_int(regs, "rip")
        rsp_val = _reg_int(regs, "rsp")
        if rip_val is not None:
            if rip_val > 0x4000000000000000:
                return "Stack Buffer Overflow", "HIGH"
            if rsp_val is not None and abs(rip_val - rsp_val) < 0x10000:
                return "Stack Buffer Overflow", "HIGH"

        # Null deref only if fault is near-zero AND stack looks clean
        corrupted_frames = backtrace.count("in ?? ()")
        if fault_addr is not None and fault_addr < 0x1000 and corrupted_frames < 2:
            return "Null Pointer Dereference", "LOW"

        return "Stack Buffer Overflow", "HIGH"

    return "Unknown Crash", "LOW"


def _reg_int(regs: dict, name: str) -> Optional[int]:
    val = regs.get(name)
    if val is None:
        return None
    try:
        return int(val, 16)
    except ValueError:
        return None


def _run_gdb(binary: str, crash_file: str) -> str:
    cmd = [
        "gdb", "-q", "-batch",
        "-ex", f"run < {crash_file}",
        "-ex", "info registers",
        "-ex", "bt 20",
        "-ex", "x/4i $rip",
        binary,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout + r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _parse_signal(gdb_out: str) -> str:
    for pat in (
        r"Program received signal (\w+)",
        r"Program terminated with signal (\w+)",
    ):
        m = re.search(pat, gdb_out)
        if m:
            return m.group(1)
    return "UNKNOWN"


def _parse_fault_addr(gdb_out: str, regs: dict) -> Optional[int]:
    m = re.search(r"Address (0x[0-9a-fA-F]+)", gdb_out)
    if m:
        return int(m.group(1), 16)
    return _reg_int(regs, "rip")


def _parse_registers(gdb_out: str) -> dict[str, str]:
    regs: dict[str, str] = {}
    for line in gdb_out.splitlines():
        m = re.match(r"(\w+)\s+(0x[0-9a-fA-F]+)", line)
        if m:
            regs[m.group(1)] = m.group(2)
    return regs


def _parse_backtrace(gdb_out: str) -> list[str]:
    return [
        line.strip()
        for line in gdb_out.splitlines()
        if re.match(r"#\d+", line.strip())
    ]


def _stack_hash(frames: list[str]) -> str:
    names = []
    for f in frames[:5]:
        m = re.search(r"in (\w+)", f)
        if m:
            names.append(m.group(1))
        else:
            # use the address if no function name
            m = re.search(r"(0x[0-9a-fA-F]+)", f)
            if m:
                names.append(m.group(1))
    digest: str = hashlib.sha1("|".join(names).encode()).hexdigest()
    return digest[:12]


class CrashAnalyzer:
    def __init__(self, target: str):
        self.target  = target
        self.reports: list[CrashReport] = []
        self._seen_hashes: set[str] = set()

    def analyze_dir(self, crashes_dir: str) -> list[CrashReport]:
        p = Path(crashes_dir)
        if not p.is_dir():
            raise FileNotFoundError(f"Crashes directory not found: {crashes_dir}")

        crash_files = sorted(f for f in p.iterdir() if f.is_file())
        if not crash_files:
            print("  No crash files found.")
            return []

        self.reports = []
        self._seen_hashes = set()

        for cf in crash_files:
            report = self._analyze_one(str(cf))
            if report:
                # Deduplicate by stack hash
                if report.stack_hash not in self._seen_hashes:
                    self._seen_hashes.add(report.stack_hash)
                    self.reports.append(report)

        self.reports.sort(key=lambda r: _RISK_ORDER.get(r.risk, 99))
        return self.reports

    def _analyze_one(self, crash_file: str) -> Optional[CrashReport]:
        gdb_out = _run_gdb(self.target, crash_file)
        if not gdb_out:
            return None

        signal    = _parse_signal(gdb_out)
        regs      = _parse_registers(gdb_out)
        backtrace = _parse_backtrace(gdb_out)
        bt_str    = " ".join(backtrace)
        fault_int = _parse_fault_addr(gdb_out, regs)
        fault_str = f"0x{fault_int:x}" if fault_int is not None else None

        crash_type, risk = _classify(signal, fault_int, bt_str, regs)
        s_hash    = _stack_hash(backtrace)
        repro     = f"cat {crash_file} | {self.target}"

        return CrashReport(
            crash_file=crash_file,
            signal=signal,
            crash_type=crash_type,
            risk=risk,
            fault_addr=fault_str,
            backtrace=backtrace,
            stack_hash=s_hash,
            repro_cmd=repro,
            gdb_output=gdb_out,
        )

    def print_report(self, fmt: str = "text"):
        if fmt == "json":
            self._print_json()
        else:
            self._print_text()

    def _print_text(self):
        colors = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[34m", "CRITICAL": "\033[91m"}
        reset  = "\033[0m"

        total = len(self.reports)
        print(f"\n  {total} unique crash(es) after deduplication\n")

        for r in self.reports:
            c   = colors.get(r.risk, "")
            tag = f"[{r.risk}]"
            print(f"  {c}{tag:10s}{reset}  {r.crash_type}  (signal={r.signal})")
            print(f"             File  : {r.crash_file}")
            if r.fault_addr:
                print(f"             Fault : {r.fault_addr}")
            print(f"             Hash  : {r.stack_hash}")
            print(f"             Repro : {r.repro_cmd}")
            if r.backtrace:
                print("             Trace :")
                for frame in r.backtrace[:5]:
                    print(f"               {frame}")
            print()

    def _print_json(self):
        import json
        out = []
        for r in self.reports:
            out.append({
                "file":       r.crash_file,
                "signal":     r.signal,
                "type":       r.crash_type,
                "risk":       r.risk,
                "fault_addr": r.fault_addr,
                "hash":       r.stack_hash,
                "repro":      r.repro_cmd,
                "backtrace":  r.backtrace[:5],
            })
        print(json.dumps(out, indent=2))

