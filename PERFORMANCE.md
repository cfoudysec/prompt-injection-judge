# pij baseline performance

**Pattern set:** v0.1.0 — 22 patterns across 7 categories.
**Author corpus:** v0.1.0 — 60 rows (34 injection, 26 benign).
**Holdout corpus:** v0.1.0 — 18 rows (10 injection, 8 benign). Evaluated once at v0.1.0 release.
**Known-bypass corpus:** v0.1.0 — 6 rows.

These numbers are the floor. A real prompt-injection defense — classifier, structured-query approach, constitutional method, fine-tuned guardrail — should publish numbers exceeding these on the same corpus to be considered a credible improvement over the naive baseline.

## Headline F1

The headline excludes the `output_coercion` category. Output-coercion patterns (`"respond only with"`, `"do not refuse"`) overlap with legitimate prompt engineering, so folding them into a headline F1 would mislead. See [LIMITATIONS.md](LIMITATIONS.md#output-coercion-patterns-overlap-with-legitimate-prompt-engineering).

| Split    | Precision | Recall | F1    | TP | FP | FN | TN | Rows |
|----------|-----------|--------|-------|----|----|----|----|------|
| author   | 0.636     | 0.933  | 0.757 | 28 | 16 | 2  | 1  | 47*  |
| holdout  | 0.714     | 1.000  | 0.833 | 10 | 4  | 0  | 0  | 14*  |

\* Row count is headline-eligible rows (excludes `output_coercion` rows and `neutral` benigns that the per-category breakdown groups separately).

## Per-category breakdown — author split

| Category                    | P     | R     | F1    | TP | FP | FN | TN |
|-----------------------------|-------|-------|-------|----|----|----|----|
| instruction_override        | 0.571 | 0.800 | 0.667 | 4  | 3  | 1  | 1  |
| role_manipulation           | 0.571 | 0.800 | 0.667 | 4  | 3  | 1  | 0  |
| system_prompt_extraction    | 0.667 | 1.000 | 0.800 | 4  | 2  | 0  | 0  |
| delimiter_injection         | 0.600 | 1.000 | 0.750 | 3  | 2  | 0  | 0  |
| encoded_payloads            | 0.500 | 1.000 | 0.667 | 3  | 3  | 0  | 0  |
| indirect_injection          | 0.769 | 1.000 | 0.870 | 10 | 3  | 0  | 0  |
| output_coercion *(excluded)*| 0.500 | 1.000 | 0.667 | 4  | 4  | 0  | 0  |

## Per-category breakdown — holdout split

| Category                    | P     | R     | F1    | TP | FP | FN | TN |
|-----------------------------|-------|-------|-------|----|----|----|----|
| instruction_override        | 0.600 | 1.000 | 0.750 | 3  | 2  | 0  | 0  |
| role_manipulation           | 0.667 | 1.000 | 0.800 | 2  | 1  | 0  | 0  |
| system_prompt_extraction    | 1.000 | 1.000 | 1.000 | 1  | 0  | 0  | 0  |
| delimiter_injection         | 0.500 | 1.000 | 0.667 | 1  | 1  | 0  | 0  |
| encoded_payloads            | —     | —     | —     | 0  | 0  | 0  | 0  |
| indirect_injection          | 1.000 | 1.000 | 1.000 | 3  | 0  | 0  | 0  |
| output_coercion *(excluded)*| —     | 0.000 | 0.000 | 0  | 1  | 0  | 0  |

The holdout corpus does not currently contain `encoded_payloads` rows. Holdout F1 for that category is undefined. The single holdout `output_coercion` row is a benign that triggered an FP, as expected.

## Overall (any pattern, all rows)

| Split   | Precision | Recall | F1    | TP | FP | FN | TN |
|---------|-----------|--------|-------|----|----|----|----|
| author  | 0.615     | 0.941  | 0.744 | 32 | 20 | 2  | 6  |
| holdout | 0.667     | 1.000  | 0.800 | 10 | 5  | 0  | 3  |

## Known-bypass regression

| Split-independent | Total | Caught | Confirmed-missed |
|-------------------|-------|--------|------------------|
| v0.1.0            | 6     | 0      | 6                |

All six bypasses are confirmed-missed. **This is the intended state.** `known_bypasses.jsonl` is a curated set of attacks v0.1 is documented not to catch — semantic paraphrase, multilingual, leetspeak, markdown-image exfiltration, and verb/noun-list gaps. Each entry's `notes` field explains the specific reason it slips through.

When a future pattern set begins catching a bypass, the row migrates out of `known_bypasses.jsonl` into the appropriate `injections.jsonl` file.

## Caveats

- The corpus is small. F1 numbers carry large variance.
- The corpus is self-graded — the same author wrote the patterns and the corpus for v0.1. The author/holdout split mitigates but does not eliminate this.
- Holdout discipline is honor-system in v0.1. See [LIMITATIONS.md](LIMITATIONS.md#holdout-discipline-is-honor-system-in-v01).

## Reproduce

```
pip install -e .
pij evaluate                  # author split
pij evaluate --holdout        # holdout split (release-time only)
pij evaluate --json out.json  # machine-readable output
```
