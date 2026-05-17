# Contributing to pij

## Holdout discipline (hard rule)

**Pattern development must use only `corpus/author/`.** Pull requests showing evidence of holdout-tuning will be rejected. Examples of what counts as evidence:

- Running `pij evaluate --holdout` during a PR
- Inspecting `corpus/holdout/*.jsonl` and then adding or modifying patterns
- Citing holdout metrics in the PR description as justification for a change

The holdout split exists to give us an honest read on baseline performance. Tuning patterns against it destroys that read for everyone, permanently. If you need a third corpus to validate a change, create a new author-side file under `corpus/author/`.

`pij evaluate --holdout` is run once at release time by the maintainer. Numbers go into `PERFORMANCE.md`. That's the only time holdout numbers appear in the project history.

## Adding a pattern

Patterns live in `pij/patterns.py` as `Pattern` dataclass instances. Every pattern must:

1. Have a unique ID of the form `<category>_NNN` (e.g. `instruction_override_005`).
2. Belong to one of the seven categories defined in `CATEGORIES`.
3. Declare a non-empty `source` — a URL, a paper citation, or the literal string `"hand-crafted"`.
4. Declare an `expected_fp_rate` from `{"low", "medium", "high", "very high"}`.
5. Compile under Python's `re` module.

Module-load validation (`_validate_patterns` in `pij/patterns.py`) enforces all of these. An invalid pattern fails at import time, before any test runs.

If your pattern belongs to a headline-excluded category (currently only `output_coercion`), it must declare `expected_fp_rate="very high"`. The validator rejects anything else.

## Adding corpus rows

Schema is documented in [corpus/README.md](corpus/README.md). All six fields are required: `id`, `text`, `label`, `category`, `source`, `notes`. The `source` and `notes` fields are required non-empty strings.

For `source`, prefer:
- A URL or paper citation when the text is drawn from a published source.
- `"representative example inspired by <citation>"` when the text is paraphrased from a published attack.
- `"hand-crafted"` or `"hand-crafted adversarial benign"` when it's original.

Verbatim copies from published attacks are discouraged. They invite questions about derivative work and licensing, and they add little to a regex corpus.

## Adding a known bypass

Demonstrating an attack `pij` misses is a valuable contribution. Add a row to `corpus/known_bypasses.jsonl` with:

- `label: "injection"`
- `category`: the category this attack would belong to if caught
- `notes`: a one-sentence explanation of **why** the v0.1 patterns miss it (e.g., "uses 'what came before' — not in the v0.1 noun list")

Do not also add a pattern that catches it in the same PR. Split into two PRs so the regression suite can demonstrably document the gap before it's closed.

## Running tests

```
python -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/pytest
```

All tests must pass before a PR can merge. Pattern additions should include at least one test case in `tests/test_detector.py` exercising the new pattern.

## Updating PERFORMANCE.md

After any change to patterns or to `corpus/author/`, regenerate the author-split numbers:

```
pij evaluate --json eval-author.json
```

Update the relevant tables in `PERFORMANCE.md`. **Do not regenerate the holdout numbers** unless you are cutting a release; that is a holdout-tuning event by another name.

## Code style

- Standard library only at runtime. No new runtime dependencies.
- `pytest` is the only dev dependency.
- Pure-function style where reasonable; dataclasses for data containers.
- No comments explaining *what* the code does — well-named identifiers handle that. Comments are reserved for non-obvious *why*: hidden constraints, design rationale, deliberate trade-offs.

## Issue reports

When reporting a false positive, include:

- The exact input text
- The pattern ID that matched (from `pij scan --json`)
- Why the input is benign

When reporting a missed attack, include:

- The exact input text
- The category you believe it belongs to
- A citation (URL or paper) where the attack class is documented, if applicable
