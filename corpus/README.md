# Corpus

The labeled dataset that `pij`'s evaluation harness reads.

## Layout

```
corpus/
├── author/
│   ├── injections.jsonl   # positive examples — open for pattern tuning
│   └── benign.jsonl       # negative examples (adversarial + neutral)
├── holdout/
│   ├── injections.jsonl   # SEALED — release-time evaluation only
│   └── benign.jsonl       # SEALED
└── known_bypasses.jsonl   # attacks v0.1 confirmed to miss (regression suite)
```

## Schema

Each row is one JSON object on one line. **All six fields are required and must be non-empty strings.** The validator in `pij/evaluate.py:load_corpus` rejects any row that does not conform.

| Field      | Description |
|------------|-------------|
| `id`       | Unique within the file. Convention: `inj_<cat>_NNN` (author injection), `ben_<cat>_NNN` (author benign), `ho_inj_NNN` / `ho_ben_NNN` (holdout), `byp_NNN` (known bypass). |
| `text`     | The prompt or text fragment to scan. Multi-line content is allowed; use JSON escape sequences. |
| `label`    | Either `"injection"` or `"benign"`. |
| `category` | One of the seven attack categories, or the sentinel `"neutral"` for benign rows that don't resemble any specific attack. |
| `source`   | URL, paper citation, or `"hand-crafted"` / `"hand-crafted adversarial benign"`. Required for traceability — see [CONTRIBUTING.md](../CONTRIBUTING.md#adding-corpus-rows) for the citation policy. |
| `notes`    | Why this row is in the corpus, and what behavior to expect (FP, FN, TN). Required because corpus rows decay without context. |

## Split policy

- **`author/`** is open for tuning. Pattern authors may inspect rows, add adversarial examples, and iterate against the metrics.
- **`holdout/`** is sealed. Do not inspect during pattern development. Do not run `pij evaluate --holdout` during tuning. Only the v0.1 release evaluated against it; the next release will be the next time. The discipline is honor-system in v0.1 — see [LIMITATIONS.md](../LIMITATIONS.md#holdout-discipline-is-honor-system-in-v01).

`pij evaluate --holdout` prints a prominent warning when invoked. The warning is a reminder, not enforcement.

## `known_bypasses.jsonl`

A curated regression suite of attacks that v0.1 is documented *not* to catch — semantic paraphrases, multilingual attacks, leetspeak, markdown-image exfiltration, verb/noun-list gaps. Each row's `notes` field explains the specific reason it slips through.

Hit rate is reported as a first-class evaluation metric so that what we don't catch is visible alongside what we do. When a future pattern set begins catching one of these bypasses, the row migrates out of `known_bypasses.jsonl` into the appropriate `injections.jsonl` file — ideally into `holdout/`, since a catch on a previously-missed attack reflects genuine generalization rather than tuning.

## Categories

The seven attack categories (defined in `pij/patterns.py`):

1. `instruction_override`
2. `role_manipulation`
3. `system_prompt_extraction`
4. `delimiter_injection`
5. `encoded_payloads`
6. `indirect_injection`
7. `output_coercion`  *(excluded from headline F1)*

Plus the corpus-only sentinel:

- `neutral` — for benign rows that don't target any specific attack category (pangrams, ordinary requests, unrelated technical content).

## A note on the JWT in `ben_enc_001`

The author-benign row `ben_enc_001` contains the canonical demo JWT from jwt.io (subject `1234567890`, name `John Doe`, signing secret `your-256-bit-secret`). This is a widely-published test fixture, **not a real credential**. It is included to exercise the `encoded_payloads_001` false-positive case — long base64-shape strings appear in JWTs, hashes, image digests, and other legitimate data.
