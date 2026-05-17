"""Evaluation: corpus loading, validation, and metric computation.

The evaluation methodology is deliberately conservative:

  * Per-category metrics use only rows whose declared `category` matches
    that pattern category, evaluated against only that category's patterns.
    This tells you how well each detector slice does on its own corpus slice.

  * Overall metrics ('all rows, any pattern') answer a different question:
    if you ran the whole detector on the whole corpus, how does it score?

  * Headline metrics aggregate per-category metrics *excluding*
    output_coercion. Output_coercion patterns are reported as a separate
    sub-metric because their phrasing routinely overlaps with legitimate
    prompt engineering — folding them into the headline F1 would mislead
    about what the baseline measures.

  * known_bypasses.jsonl is a regression suite of attacks we know we
    miss. Its hit rate is reported as a first-class metric so that what
    we don't catch is visible alongside what we do.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pij.detector import any_match, scan
from pij.patterns import (
    CATEGORIES,
    HEADLINE_EXCLUDED_CATEGORIES,
    PATTERNS,
    Pattern,
    VALID_ROW_CATEGORIES,
    patterns_by_category,
)


REQUIRED_FIELDS: tuple[str, ...] = (
    "id",
    "text",
    "label",
    "category",
    "source",
    "notes",
)

VALID_LABELS: tuple[str, ...] = ("injection", "benign")


class CorpusValidationError(ValueError):
    """Raised when a corpus row is missing required fields or has bad values."""


@dataclass(frozen=True)
class CorpusRow:
    id: str
    text: str
    label: str
    category: str
    source: str
    notes: str


@dataclass
class CategoryMetrics:
    category: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    fp_ids: list[str] = field(default_factory=list)
    fn_ids: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def support_positive(self) -> int:
        return self.tp + self.fn

    @property
    def support_negative(self) -> int:
        return self.tn + self.fp


@dataclass
class EvaluationResult:
    per_category: dict[str, CategoryMetrics]
    headline: CategoryMetrics  # aggregate excluding HEADLINE_EXCLUDED_CATEGORIES
    overall: CategoryMetrics  # any pattern, all rows
    output_coercion_submetric: CategoryMetrics | None
    bypasses_total: int
    bypasses_caught: int
    bypasses_missed: int
    bypass_miss_ids: list[str]
    corpus_split: str  # "author" or "holdout"
    pattern_count: int
    row_count: int


# ─── corpus loading & validation ─────────────────────────────────────────


def load_corpus(path: Path) -> list[CorpusRow]:
    """Load and validate a corpus JSONL file.

    Every row must contain all REQUIRED_FIELDS as non-null values. Label
    must be in VALID_LABELS. Category must be in VALID_ROW_CATEGORIES.
    Source and notes must be non-empty strings (per the schema policy in
    corpus/README.md — these fields are required for traceability).
    """
    rows: list[CorpusRow] = []
    with path.open(encoding="utf-8") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise CorpusValidationError(f"{path}:{line_no} invalid JSON: {e}") from e

            missing = [k for k in REQUIRED_FIELDS if k not in obj]
            if missing:
                raise CorpusValidationError(
                    f"{path}:{line_no} missing required fields: {missing}"
                )
            for k in REQUIRED_FIELDS:
                if not isinstance(obj[k], str):
                    raise CorpusValidationError(
                        f"{path}:{line_no} field {k!r} must be a string"
                    )
            if obj["label"] not in VALID_LABELS:
                raise CorpusValidationError(
                    f"{path}:{line_no} label {obj['label']!r} not in {VALID_LABELS}"
                )
            if obj["category"] not in VALID_ROW_CATEGORIES:
                raise CorpusValidationError(
                    f"{path}:{line_no} category {obj['category']!r} not in {VALID_ROW_CATEGORIES}"
                )
            for k in ("id", "text", "source", "notes"):
                if not obj[k].strip():
                    raise CorpusValidationError(
                        f"{path}:{line_no} field {k!r} must be a non-empty string"
                    )

            rows.append(CorpusRow(**{k: obj[k] for k in REQUIRED_FIELDS}))

    ids = [r.id for r in rows]
    if len(set(ids)) != len(ids):
        dups = sorted({i for i in ids if ids.count(i) > 1})
        raise CorpusValidationError(f"{path}: duplicate row ids: {dups}")

    return rows


# ─── metric computation ──────────────────────────────────────────────────


def _binary_metrics(
    rows: Sequence[CorpusRow], patterns: Sequence[Pattern], label_for: str
) -> CategoryMetrics:
    """Compute confusion-matrix metrics over `rows` using `patterns`.

    A row is "predicted injection" iff any of `patterns` matches its text.
    The metric is labeled `label_for` (a category name, or "headline", etc.).
    """
    m = CategoryMetrics(category=label_for)
    for r in rows:
        flagged = any_match(r.text, patterns)
        if r.label == "injection":
            if flagged:
                m.tp += 1
            else:
                m.fn += 1
                m.fn_ids.append(r.id)
        else:  # benign
            if flagged:
                m.fp += 1
                m.fp_ids.append(r.id)
            else:
                m.tn += 1
    return m


def evaluate(
    rows: Sequence[CorpusRow],
    bypasses: Sequence[CorpusRow] = (),
    patterns: Sequence[Pattern] = PATTERNS,
    corpus_split: str = "author",
) -> EvaluationResult:
    """Compute the full evaluation result for `rows`.

    `bypasses` are the known-miss corpus; their hit rate (which should be
    zero or close to it — these are attacks we don't catch) is reported
    as a first-class metric.
    """
    per_category: dict[str, CategoryMetrics] = {}
    for cat in CATEGORIES:
        cat_rows = [r for r in rows if r.category == cat]
        cat_patterns = patterns_by_category(cat)
        m = _binary_metrics(cat_rows, cat_patterns, label_for=cat)
        per_category[cat] = m

    # Headline: aggregate per-category metrics across non-excluded categories.
    # Aggregating raw counts is equivalent to micro-averaging.
    headline = CategoryMetrics(category="headline")
    for cat, m in per_category.items():
        if cat in HEADLINE_EXCLUDED_CATEGORIES:
            continue
        headline.tp += m.tp
        headline.fp += m.fp
        headline.fn += m.fn
        headline.tn += m.tn
        headline.fp_ids.extend(m.fp_ids)
        headline.fn_ids.extend(m.fn_ids)

    # Overall: every row evaluated against every pattern.
    overall = _binary_metrics(rows, patterns, label_for="overall")

    output_coercion_submetric = per_category.get("output_coercion")

    # Bypass regression suite.
    bypass_miss_ids: list[str] = []
    bypasses_caught = 0
    for b in bypasses:
        if any_match(b.text, patterns):
            bypasses_caught += 1
        else:
            bypass_miss_ids.append(b.id)

    return EvaluationResult(
        per_category=per_category,
        headline=headline,
        overall=overall,
        output_coercion_submetric=output_coercion_submetric,
        bypasses_total=len(bypasses),
        bypasses_caught=bypasses_caught,
        bypasses_missed=len(bypass_miss_ids),
        bypass_miss_ids=bypass_miss_ids,
        corpus_split=corpus_split,
        pattern_count=len(patterns),
        row_count=len(rows),
    )
