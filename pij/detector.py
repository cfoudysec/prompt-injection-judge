"""Detection logic for pij.

Applies the pattern taxonomy to text and returns Finding objects.
All findings carry confidence='low' — a regex match is evidence of
*shape*, not of intent. Downstream code is responsible for verdicts.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from pij.patterns import PATTERNS, Pattern


CONFIDENCE_LOW = "low"


@dataclass(frozen=True)
class Finding:
    pattern_id: str
    category: str
    matched_text: str
    start: int
    end: int
    confidence: str = CONFIDENCE_LOW


def scan(text: str, patterns: Sequence[Pattern] = PATTERNS) -> list[Finding]:
    """Apply every pattern to `text` and return matches in source order.

    Matches are reported in (pattern-index, start-offset) order. Overlapping
    matches across patterns are all reported; callers that want a deduplicated
    span set must do their own merging.
    """
    findings: list[Finding] = []
    for pattern in patterns:
        for match in re.finditer(pattern.regex, text):
            findings.append(
                Finding(
                    pattern_id=pattern.id,
                    category=pattern.category,
                    matched_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return findings


def any_match(text: str, patterns: Sequence[Pattern] = PATTERNS) -> bool:
    """Return True if any pattern matches `text`. Short-circuits on first hit."""
    for pattern in patterns:
        if re.search(pattern.regex, text) is not None:
            return True
    return False
