"""Output formatters for pij.

Two output modes for each report: human-readable text and JSON. Output
language stays epistemic — we report 'matched pattern X', never 'this is
injection' or 'blocked'. Verdicts are downstream concerns.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict

from pij.detector import Finding
from pij.evaluate import CategoryMetrics, CorpusRow, EvaluationResult
from pij.patterns import (
    CATEGORIES,
    HEADLINE_EXCLUDED_CATEGORIES,
    PATTERNS,
    Pattern,
)


def _truncate(s: str, limit: int = 80) -> str:
    s = s.replace("\n", "\\n")
    if len(s) <= limit:
        return s
    return s[: limit - 1] + "…"


# ─── scan output ─────────────────────────────────────────────────────────


def render_scan_text(findings: Sequence[Finding]) -> str:
    if not findings:
        return "no patterns matched (confidence: not evidence of safety)"
    lines = [f"{len(findings)} pattern match(es) — all confidence=low:"]
    for f in findings:
        lines.append(
            f"  [{f.category}] {f.pattern_id}  @{f.start}-{f.end}  "
            f"matched: {_truncate(f.matched_text)!r}"
        )
    return "\n".join(lines)


def render_scan_json(findings: Sequence[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)


# ─── evaluation output ───────────────────────────────────────────────────


def _fmt_metric_line(m: CategoryMetrics) -> str:
    return (
        f"p={m.precision:6.3f}  r={m.recall:6.3f}  f1={m.f1:6.3f}  "
        f"tp={m.tp:4d} fp={m.fp:4d} fn={m.fn:4d} tn={m.tn:4d}  "
        f"(pos={m.support_positive}, neg={m.support_negative})"
    )


def render_evaluation_text(result: EvaluationResult) -> str:
    lines: list[str] = []
    lines.append(f"=== pij evaluation ({result.corpus_split} split) ===")
    lines.append(
        f"  rows: {result.row_count}    patterns: {result.pattern_count}"
    )
    lines.append("")
    lines.append(
        f"  HEADLINE  (excludes {', '.join(HEADLINE_EXCLUDED_CATEGORIES)})"
    )
    lines.append(f"    {_fmt_metric_line(result.headline)}")
    lines.append("")
    lines.append("  PER-CATEGORY")
    for cat in CATEGORIES:
        m = result.per_category[cat]
        flag = "  (excluded from headline)" if cat in HEADLINE_EXCLUDED_CATEGORIES else ""
        lines.append(f"    {cat:30s} {_fmt_metric_line(m)}{flag}")
    lines.append("")
    lines.append("  OVERALL  (any pattern, all rows)")
    lines.append(f"    {_fmt_metric_line(result.overall)}")
    lines.append("")
    if result.output_coercion_submetric:
        lines.append("  OUTPUT-COERCION SUB-METRIC (reported separately)")
        lines.append(f"    {_fmt_metric_line(result.output_coercion_submetric)}")
        lines.append("")
    lines.append("  KNOWN-BYPASS REGRESSION")
    lines.append(
        f"    total={result.bypasses_total}  caught={result.bypasses_caught}  "
        f"missed={result.bypasses_missed}"
    )
    if result.bypass_miss_ids:
        lines.append(f"    confirmed-missed ids: {', '.join(result.bypass_miss_ids)}")
    lines.append("")
    if result.headline.fp_ids:
        lines.append(
            f"  HEADLINE FALSE POSITIVES ({len(result.headline.fp_ids)}): "
            f"{', '.join(result.headline.fp_ids)}"
        )
    if result.headline.fn_ids:
        lines.append(
            f"  HEADLINE FALSE NEGATIVES ({len(result.headline.fn_ids)}): "
            f"{', '.join(result.headline.fn_ids)}"
        )
    return "\n".join(lines)


def _metric_to_dict(m: CategoryMetrics) -> dict:
    return {
        "category": m.category,
        "tp": m.tp,
        "fp": m.fp,
        "fn": m.fn,
        "tn": m.tn,
        "precision": m.precision,
        "recall": m.recall,
        "f1": m.f1,
        "fp_ids": list(m.fp_ids),
        "fn_ids": list(m.fn_ids),
        "support_positive": m.support_positive,
        "support_negative": m.support_negative,
    }


def render_evaluation_json(result: EvaluationResult) -> str:
    payload = {
        "corpus_split": result.corpus_split,
        "row_count": result.row_count,
        "pattern_count": result.pattern_count,
        "headline_excluded_categories": list(HEADLINE_EXCLUDED_CATEGORIES),
        "headline": _metric_to_dict(result.headline),
        "overall": _metric_to_dict(result.overall),
        "per_category": {
            cat: _metric_to_dict(m) for cat, m in result.per_category.items()
        },
        "output_coercion_submetric": (
            _metric_to_dict(result.output_coercion_submetric)
            if result.output_coercion_submetric
            else None
        ),
        "bypasses": {
            "total": result.bypasses_total,
            "caught": result.bypasses_caught,
            "missed": result.bypasses_missed,
            "miss_ids": list(result.bypass_miss_ids),
        },
    }
    return json.dumps(payload, indent=2)


# ─── patterns listing ────────────────────────────────────────────────────


def render_patterns_text(patterns: Sequence[Pattern] = PATTERNS) -> str:
    lines: list[str] = []
    lines.append(f"=== pij pattern taxonomy ({len(patterns)} patterns) ===")
    by_cat: dict[str, list[Pattern]] = {c: [] for c in CATEGORIES}
    for p in patterns:
        by_cat[p.category].append(p)
    for cat in CATEGORIES:
        flag = "  [excluded from headline F1]" if cat in HEADLINE_EXCLUDED_CATEGORIES else ""
        lines.append("")
        lines.append(f"── {cat}{flag}")
        for p in by_cat[cat]:
            lines.append(f"  {p.id}  (expected_fp={p.expected_fp_rate})")
            lines.append(f"    {p.description}")
            lines.append(f"    regex:  {p.regex}")
            lines.append(f"    source: {p.source}")
            if p.notes:
                lines.append(f"    notes:  {p.notes}")
    return "\n".join(lines)


def render_patterns_json(patterns: Sequence[Pattern] = PATTERNS) -> str:
    return json.dumps([asdict(p) for p in patterns], indent=2)


# ─── self-test ───────────────────────────────────────────────────────────


def render_selftest_text(
    expected_fps: Sequence[tuple[CorpusRow, list[Finding]]],
    expected_misses: Sequence[CorpusRow],
) -> str:
    lines: list[str] = []
    lines.append("=== pij self-test ===")
    lines.append("")
    lines.append("Use this output to understand the tool's limits before relying on it.")
    lines.append("")
    lines.append(
        f"EXPECTED FALSE POSITIVES  ({len(expected_fps)} benign rows that the "
        f"detector flags)"
    )
    if not expected_fps:
        lines.append("  (none in the current author corpus)")
    for row, findings in expected_fps:
        cats = sorted({f.category for f in findings})
        lines.append(f"  {row.id}  category={row.category}  flagged by: {', '.join(cats)}")
        lines.append(f"    text:   {_truncate(row.text, 100)!r}")
        lines.append(f"    notes:  {row.notes}")
    lines.append("")
    lines.append(
        f"EXPECTED MISSES  ({len(expected_misses)} attacks from known_bypasses.jsonl "
        f"that the detector does not catch)"
    )
    if not expected_misses:
        lines.append("  (none — but absence of known bypasses does not mean coverage is complete)")
    for row in expected_misses:
        lines.append(f"  {row.id}  category={row.category}")
        lines.append(f"    text:   {_truncate(row.text, 100)!r}")
        lines.append(f"    notes:  {row.notes}")
        lines.append(f"    source: {row.source}")
    return "\n".join(lines)
