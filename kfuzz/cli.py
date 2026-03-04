import argparse
import sys

from .config import FuzzerConfig
from .engine.fuzzer import Fuzzer
from .triage.crash_analyzer import CrashAnalyzer
from .triage.dangerous_functions import DangerousFunctionDetector


def cmd_triage(args):
    analyzer = CrashAnalyzer(args.target)
    analyzer.analyze_dir(args.crashes)
    analyzer.print_report(fmt=args.format)


def cmd_scan(args):
    det = DangerousFunctionDetector(args.target)
    det.analyze()
    det.print_report()


def cmd_fuzz(args):
    config = FuzzerConfig(
        target=args.target,
        input_dir=args.input,
        output_dir=args.output,
        timeout_ms=args.timeout,
        qemu_mode=args.qemu,
        max_time=args.max_time,
        max_execs=args.max_execs,
    )
    fuzzer = Fuzzer(config)
    fuzzer.setup()
    fuzzer.load_seeds()
    fuzzer.dry_run()
    fuzzer.run()


VERSION = "1.1"

BANNER = f"""\
kfuzz v{VERSION} — coverage-guided binary fuzzer

Commands:
  scan    <-t binary>                          Scan for dangerous functions
  fuzz    <-t binary> <-i seeds> <-o output>  Fuzz a target
  triage  <-c crashes> <-t binary>            Classify crashes under GDB

Use 'kfuzz <command> -h' for per-command options.
"""


def main():
    parser = argparse.ArgumentParser(
        prog="kfuzz",
        add_help=True,
    )
    parser.add_argument("-v", "--version", action="version", version=f"kfuzz {VERSION}")
    sub = parser.add_subparsers(dest="command")

    fuzz = sub.add_parser("fuzz", help="Fuzz a target binary")
    fuzz.add_argument("-t", "--target",   required=True)
    fuzz.add_argument("-i", "--input",    required=True)
    fuzz.add_argument("-o", "--output",   required=True)
    fuzz.add_argument("--timeout",        type=int, default=1000, metavar="MS")
    fuzz.add_argument("--qemu",           action="store_true")
    fuzz.add_argument("--max-time",       type=int, default=0,    metavar="SEC", dest="max_time")
    fuzz.add_argument("--max-execs",      type=int, default=0,    dest="max_execs")

    scan = sub.add_parser("scan", help="Scan a binary for dangerous functions")
    scan.add_argument("-t", "--target", required=True)

    triage = sub.add_parser("triage", help="Classify crash inputs under GDB")
    triage.add_argument("-c", "--crashes", required=True, metavar="DIR")
    triage.add_argument("-t", "--target",  required=True)
    triage.add_argument("--format", choices=["text", "json"], default="text")

    args = parser.parse_args()

    if args.command is None:
        print(BANNER)
        sys.exit(0)

    if args.command == "fuzz":
        cmd_fuzz(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "triage":
        cmd_triage(args)


if __name__ == "__main__":
    main()
