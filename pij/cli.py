"""argparse CLI for pij. Stdlib only on purpose.

Subcommands:
  scan        scan text for pattern matches
  evaluate    evaluate against corpus (defaults to author/; --holdout opt-in)
  self-test   show expected false-positives and known misses
  patterns    list the pattern taxonomy
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pij import __version__, report
from pij.detector import scan as scan_text
from pij.evaluate import (
    CorpusValidationError,
    evaluate,
    load_corpus,
)
from pij.patterns import PATTERNS

# Severity tiers. All current patterns emit confidence='low', but the
# flag is wired so that future versions can introduce higher tiers
# without breaking the CLI contract.
SEVERITY_ORDER = {"low": 0}


def _read_input(file_arg: str) -> str:
    if file_arg == "-":
        return sys.stdin.read()
    return Path(file_arg).read_text(encoding="utf-8")


def _corpus_split_dir(corpus_root: Path, use_holdout: bool) -> tuple[Path, str]:
    if use_holdout:
        return corpus_root / "holdout", "holdout"
    return corpus_root / "author", "author"


def _load_split(split_dir: Path) -> list:
    injections_path = split_dir / "injections.jsonl"
    benign_path = split_dir / "benign.jsonl"
    rows = []
    if injections_path.exists():
        rows.extend(load_corpus(injections_path))
    if benign_path.exists():
        rows.extend(load_corpus(benign_path))
    if not rows:
        raise FileNotFoundError(
            f"no corpus rows found under {split_dir} (expected injections.jsonl and/or benign.jsonl)"
        )
    return rows


# ─── subcommand handlers ─────────────────────────────────────────────────


def cmd_scan(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    findings = scan_text(text)

    min_level = SEVERITY_ORDER[args.min_severity]
    filtered = [f for f in findings if SEVERITY_ORDER.get(f.confidence, 0) >= min_level]

    if args.json:
        print(report.render_scan_json(filtered))
    else:
        print(report.render_scan_text(filtered))

    if args.strict and filtered:
        return 1
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    split_dir, split_name = _corpus_split_dir(args.corpus, args.holdout)

    if args.holdout:
        print(
            "WARNING: --holdout reads the sealed holdout corpus. This split must "
            "only be evaluated at release time; using it during pattern tuning "
            "invalidates the reported numbers.",
            file=sys.stderr,
        )

    try:
        rows = _load_split(split_dir)
    except (CorpusValidationError, FileNotFoundError) as e:
        print(f"corpus error: {e}", file=sys.stderr)
        return 2

    bypasses_path = args.corpus / "known_bypasses.jsonl"
    bypasses = load_corpus(bypasses_path) if bypasses_path.exists() else []

    result = evaluate(rows, bypasses=bypasses, corpus_split=split_name)

    if args.json:
        Path(args.json).write_text(
            report.render_evaluation_json(result), encoding="utf-8"
        )
        print(f"wrote {args.json}", file=sys.stderr)
    print(report.render_evaluation_text(result))
    return 0


def cmd_self_test(args: argparse.Namespace) -> int:
    split_dir, _ = _corpus_split_dir(args.corpus, use_holdout=False)
    benign_path = split_dir / "benign.jsonl"
    bypasses_path = args.corpus / "known_bypasses.jsonl"

    expected_fps: list = []
    if benign_path.exists():
        for row in load_corpus(benign_path):
            findings = scan_text(row.text)
            if findings:
                expected_fps.append((row, findings))

    expected_misses: list = []
    if bypasses_path.exists():
        for row in load_corpus(bypasses_path):
            findings = scan_text(row.text)
            if not findings:
                expected_misses.append(row)

    print(report.render_selftest_text(expected_fps, expected_misses))
    return 0


def cmd_patterns(args: argparse.Namespace) -> int:
    if args.json:
        print(report.render_patterns_json(PATTERNS))
    else:
        print(report.render_patterns_text(PATTERNS))
    return 0


# ─── argparse wiring ─────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pij",
        description=(
            "Prompt Injection Judge — a deliberately naive regex baseline "
            "detector. This tool is the measurement floor, not a defense."
        ),
    )
    p.add_argument("--version", action="version", version=f"pij {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # scan
    s = sub.add_parser("scan", help="scan a file or stdin for pattern matches")
    s.add_argument("file", help="path to file, or '-' for stdin")
    s.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when matches at or above --min-severity are present (default: always exit 0)",
    )
    s.add_argument(
        "--min-severity",
        choices=sorted(SEVERITY_ORDER.keys()),
        default="low",
        help="minimum severity that counts for --strict (default: low)",
    )
    s.add_argument("--json", action="store_true", help="emit JSON instead of human-readable text")
    s.set_defaults(func=cmd_scan)

    # evaluate
    e = sub.add_parser("evaluate", help="evaluate against corpus")
    e.add_argument(
        "--corpus",
        type=Path,
        default=Path("corpus"),
        help="path to corpus root (default: ./corpus)",
    )
    e.add_argument(
        "--holdout",
        action="store_true",
        help="evaluate against the sealed holdout split (prints a warning; release-time use only)",
    )
    e.add_argument("--json", metavar="PATH", help="also write JSON output to PATH")
    e.set_defaults(func=cmd_evaluate)

    # self-test
    t = sub.add_parser(
        "self-test",
        help="show expected false-positives and known-missed attacks (run this first to understand the tool's limits)",
    )
    t.add_argument(
        "--corpus",
        type=Path,
        default=Path("corpus"),
        help="path to corpus root (default: ./corpus)",
    )
    t.set_defaults(func=cmd_self_test)

    # patterns
    pat = sub.add_parser("patterns", help="list the pattern taxonomy")
    pat.add_argument("--json", action="store_true")
    pat.set_defaults(func=cmd_patterns)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
