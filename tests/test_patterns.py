"""Tests for the pattern taxonomy data contract."""

import re

import pytest

from pij.patterns import (
    CATEGORIES,
    EXPECTED_FP_RATES,
    HEADLINE_EXCLUDED_CATEGORIES,
    NEUTRAL_CATEGORY,
    PATTERNS,
    VALID_ROW_CATEGORIES,
    Pattern,
    patterns_by_category,
)


def test_all_patterns_compile():
    for p in PATTERNS:
        re.compile(p.regex)


def test_pattern_ids_unique():
    ids = [p.id for p in PATTERNS]
    assert len(set(ids)) == len(ids), f"duplicate ids: {sorted({i for i in ids if ids.count(i) > 1})}"


def test_every_pattern_has_non_empty_source():
    for p in PATTERNS:
        assert p.source.strip(), f"{p.id} missing source"


def test_every_pattern_category_in_taxonomy():
    for p in PATTERNS:
        assert p.category in CATEGORIES, f"{p.id} has unknown category {p.category!r}"


def test_every_category_has_at_least_one_pattern():
    seen = {p.category for p in PATTERNS}
    missing = set(CATEGORIES) - seen
    assert not missing, f"categories with no patterns: {missing}"


def test_expected_fp_rate_values_are_valid():
    for p in PATTERNS:
        assert p.expected_fp_rate in EXPECTED_FP_RATES, (
            f"{p.id} has invalid expected_fp_rate {p.expected_fp_rate!r}"
        )


def test_headline_excluded_categories_marked_very_high_fp():
    for p in PATTERNS:
        if p.category in HEADLINE_EXCLUDED_CATEGORIES:
            assert p.expected_fp_rate == "very high", (
                f"{p.id} is in excluded category {p.category} but expected_fp_rate is "
                f"{p.expected_fp_rate!r}, must be 'very high'"
            )


def test_neutral_is_not_a_pattern_category():
    """Neutral is a corpus-row category, not an attack category."""
    assert NEUTRAL_CATEGORY not in CATEGORIES
    assert NEUTRAL_CATEGORY in VALID_ROW_CATEGORIES


def test_patterns_by_category_returns_only_that_category():
    for cat in CATEGORIES:
        for p in patterns_by_category(cat):
            assert p.category == cat


def test_pattern_dataclass_is_frozen():
    p = PATTERNS[0]
    with pytest.raises((AttributeError, Exception)):
        # frozen dataclass disallows attribute assignment
        p.id = "mutated"  # type: ignore[misc]


def test_pattern_construction_requires_all_fields():
    with pytest.raises(TypeError):
        Pattern()  # type: ignore[call-arg]
