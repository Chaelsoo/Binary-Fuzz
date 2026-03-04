import subprocess
from dataclasses import dataclass, field
from enum import Enum


class Risk(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

    def __lt__(self, other):
        order = [Risk.CRITICAL, Risk.HIGH, Risk.MEDIUM, Risk.LOW]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    name:    str
    risk:    Risk
    reason:  str
    count:   int = 1


# ── C dangerous function catalogue ───────────────────────────────────────────

_C_FUNCTIONS: dict[str, tuple[Risk, str]] = {
    # CRITICAL
    "gets":           (Risk.CRITICAL, "No bounds checking whatsoever"),
    # HIGH
    "strcpy":         (Risk.HIGH,     "Unbounded string copy"),
    "strcat":         (Risk.HIGH,     "Unbounded string concatenation"),
    "sprintf":        (Risk.HIGH,     "Unbounded formatted write"),
    "vsprintf":       (Risk.HIGH,     "Unbounded formatted write"),
    "scanf":          (Risk.HIGH,     "Unbounded input read"),
    "system":         (Risk.HIGH,     "Shell command injection"),
    "popen":          (Risk.HIGH,     "Shell command injection"),
    "exec":           (Risk.HIGH,     "Process execution"),
    "execve":         (Risk.HIGH,     "Process execution"),
    "execvp":         (Risk.HIGH,     "Process execution"),
    # MEDIUM
    "printf":         (Risk.MEDIUM,   "Format string if user-controlled"),
    "fprintf":        (Risk.MEDIUM,   "Format string if user-controlled"),
    "vprintf":        (Risk.MEDIUM,   "Format string if user-controlled"),
    "memcpy":         (Risk.MEDIUM,   "No bounds checking on destination"),
    "memmove":        (Risk.MEDIUM,   "No bounds checking on destination"),
    "strncpy":        (Risk.MEDIUM,   "May omit null terminator"),
    "strncat":        (Risk.MEDIUM,   "Off-by-one possible"),
    "snprintf":       (Risk.MEDIUM,   "Format string if user-controlled"),
    "read":           (Risk.MEDIUM,   "No bounds checking on buffer"),
    "recv":           (Risk.MEDIUM,   "No bounds checking on buffer"),
    "fread":          (Risk.MEDIUM,   "Caller must validate size"),
    # LOW
    "malloc":         (Risk.LOW,      "Unchecked NULL return leads to deref"),
    "realloc":        (Risk.LOW,      "Unchecked NULL return leads to deref"),
    "free":           (Risk.LOW,      "Double-free / use-after-free possible"),
    "atoi":           (Risk.LOW,      "No error detection on bad input"),
    "atol":           (Risk.LOW,      "No error detection on bad input"),
    "strtok":         (Risk.LOW,      "Not thread-safe, modifies input"),
    "getenv":         (Risk.LOW,      "Env var injection possible"),
}

# ── Rust dangerous symbols ────────────────────────────────────────────────────

_RUST_PATTERNS: dict[str, tuple[Risk, str]] = {
    "core::mem::transmute":       (Risk.HIGH,   "Unsafe type transmutation"),
    "from_raw_parts":             (Risk.HIGH,   "Unsafe raw pointer to slice"),
    "from_raw":                   (Risk.HIGH,   "Unsafe raw pointer conversion"),
    "ptr::read":                  (Risk.HIGH,   "Unsafe raw pointer read"),
    "ptr::write":                 (Risk.HIGH,   "Unsafe raw pointer write"),
    "__rust_alloc":               (Risk.LOW,    "Custom allocator — check OOM handling"),
}

# ── Go dangerous patterns (visible in strings / nm output) ───────────────────

_GO_PATTERNS: dict[str, tuple[Risk, str]] = {
    "unsafe.Pointer":   (Risk.HIGH,   "Unsafe pointer cast"),
    "syscall.":         (Risk.MEDIUM, "Direct syscall — bypasses Go safety"),
    "cgo":              (Risk.MEDIUM, "CGo call — C code executed"),
    "reflect.":         (Risk.LOW,    "Reflection — type safety bypassed"),
}


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


class DangerousFunctionDetector:
    def __init__(self, binary: str):
        self.binary   = binary
        self.findings: list[Finding] = []
        self._lang    = "unknown"

    def analyze(self) -> list[Finding]:
        symbols = _run(["nm", "-D", self.binary])
        # nm without -D for statically linked binaries
        if not symbols.strip():
            symbols = _run(["nm", self.binary])
        strings  = _run(["strings", self.binary])

        self._lang = self._detect_language(symbols, strings)
        self.findings = []

        if self._lang == "rust":
            self._scan_rust(symbols, strings)
        elif self._lang == "go":
            self._scan_go(symbols, strings)
        else:
            self._scan_c(symbols, strings)

        self.findings.sort(key=lambda f: f.risk)
        return self.findings

    def print_report(self):
        if not self.findings:
            self.analyze()

        colors = {
            Risk.CRITICAL: "\033[91m",  # bright red
            Risk.HIGH:     "\033[31m",  # red
            Risk.MEDIUM:   "\033[33m",  # yellow
            Risk.LOW:      "\033[34m",  # blue
        }
        reset = "\033[0m"

        print(f"\n  Binary : {self.binary}")
        print(f"  Language detected : {self._lang}")
        print()

        if not self.findings:
            print("  No dangerous functions detected.")
            return

        for f in self.findings:
            c = colors.get(f.risk, "")
            tag = f"[{f.risk.value}]"
            count_str = f" (x{f.count})" if f.count > 1 else ""
            print(f"  {c}{tag:10s}{reset}  {f.name}{count_str}  —  {f.reason}")

        print()
        by_risk: dict[Risk, int] = {}
        for f in self.findings:
            by_risk[f.risk] = by_risk.get(f.risk, 0) + 1
        summary = "  Summary: " + "  ".join(
            f"{r.value}×{n}" for r, n in sorted(by_risk.items())
        )
        print(summary)

    # ── language detection ────────────────────────────────────────────────────

    def _detect_language(self, symbols: str, strings: str) -> str:
        if "GCC_except_table" in symbols or "__rust_alloc" in symbols or "core::panicking" in symbols:
            return "rust"
        if "runtime.gopanic" in symbols or "go.buildid" in strings:
            return "go"
        return "c"

    # ── scanners ──────────────────────────────────────────────────────────────

    def _scan_c(self, symbols: str, strings: str):
        sym_names = set()
        for line in symbols.splitlines():
            parts = line.split()
            if parts:
                sym_names.add(parts[-1])

        seen: dict[str, Finding] = {}
        for sym in sym_names:
            # strip PLT suffixes like strcpy@GLIBC_2.5
            base = sym.split("@")[0]
            if base in _C_FUNCTIONS:
                risk, reason = _C_FUNCTIONS[base]
                if base in seen:
                    seen[base].count += 1
                else:
                    seen[base] = Finding(name=base, risk=risk, reason=reason)

        self.findings.extend(seen.values())

    def _scan_rust(self, symbols: str, strings: str):
        combined = symbols + strings
        for pattern, (risk, reason) in _RUST_PATTERNS.items():
            if pattern in combined:
                self.findings.append(Finding(name=pattern, risk=risk, reason=reason))

    def _scan_go(self, symbols: str, strings: str):
        combined = symbols + strings
        for pattern, (risk, reason) in _GO_PATTERNS.items():
            if pattern in combined:
                self.findings.append(Finding(name=pattern, risk=risk, reason=reason))
