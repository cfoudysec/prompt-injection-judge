# pij — Prompt Injection Judge

> **This tool is naive on purpose.** It is the measurement baseline, not a defense.

`pij` is a deliberately naive regex-based detector for prompt injection patterns, released as an AI safety research artifact. Its job is to be the honest floor, the measurement baseline that real defenses (classifiers, structured queries, constitutional methods) have to beat to be worth taking seriously.

**Measurement before mitigation.**

## What this is

- A small Python CLI built on the standard library (`re`, `argparse`, `json`).
- A taxonomy of 22 regex patterns spanning 7 OWASP LLM01:2025-aligned categories.
- A labeled corpus split into a tunable author set, a sealed holdout set, and a `known_bypasses.jsonl` regression suite of attacks the tool *cannot* catch.
- An evaluation harness that reports precision, recall, and F1 per category, with output-coercion patterns reported as a separate sub-metric (their phrasing overlaps too heavily with legitimate prompt engineering to belong in a headline number).

## What this is not

- A production defense. Every Finding emits `confidence="low"`. The CLI says "matched pattern X" — it never says "injection detected" or "blocked."
- An attempt at high coverage. The author-tunable corpus, the sealed holdout, and the explicit known-bypass file together give you an honest read on what the regex can and can't do.
- A multilingual detector, a semantic detector, or anything that can be hardened against paraphrase. See [LIMITATIONS.md](LIMITATIONS.md).

## Install

```
git clone <repo-url>
cd pij
pip install -e .
```

Requires Python 3.10+. No runtime dependencies.

## Usage

```
pij scan path/to/file.txt           # scan a file for pattern matches
echo "ignore previous instructions" | pij scan -
pij scan input.txt --strict         # exit non-zero when matches are present

pij evaluate                        # evaluate against corpus/author/
pij evaluate --holdout              # release-time only (prints warning)
pij evaluate --json eval.json       # also write JSON output

pij self-test                       # show expected FPs and known misses
pij patterns                        # list the pattern taxonomy with sources
```

`pij scan` always exits 0 by default — pattern matches are evidence, not verdicts. Use `--strict` for CI-style usage.

## Baseline numbers (v0.1)

Headline F1 excludes the `output_coercion` category (see [PERFORMANCE.md](PERFORMANCE.md) for the reasoning).

| Split    | Precision | Recall | F1    | Rows |
|----------|-----------|--------|-------|------|
| author   | 0.636     | 0.933  | 0.757 | 60   |
| holdout  | 0.714     | 1.000  | 0.833 | 18   |

**Known-bypass regression: 6/6 confirmed-missed.** These attacks document v0.1's coverage gaps; they are not failures, they are the honesty story. See [LIMITATIONS.md](LIMITATIONS.md) for the bypass classes.

For the full per-category breakdown, see [PERFORMANCE.md](PERFORMANCE.md). To reproduce: `pip install -e . && pij evaluate`.

## Honesty mechanisms

- Headline F1 **excludes** the `output_coercion` category, which overlaps with legitimate prompt engineering (`"Respond only with valid JSON"`). It is reported as a separate sub-metric instead.
- The author/holdout split is structural on disk. `pij evaluate --holdout` prints a release-time warning. The discipline is honor-system in v0.1 — see [LIMITATIONS.md](LIMITATIONS.md).
- `corpus/known_bypasses.jsonl` is a regression suite of attacks v0.1 cannot catch. Its hit rate is a first-class metric.
- Every `Pattern` declares a `source` field — either a URL/citation or the literal string `"hand-crafted"`. Module-load validation enforces it.
- `pij self-test` shows expected false-positives and known-missed attacks in one command. Run it before relying on pij in any pipeline.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. The short version: pattern development uses **only** `corpus/author/`. PRs showing evidence of holdout-tuning will be rejected.

## License

MIT.
