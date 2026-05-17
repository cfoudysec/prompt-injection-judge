"""Pattern taxonomy for pij.

Patterns are data, not logic. Every Pattern must declare its source
(URL, paper citation, or the literal string "hand-crafted"). Module-load
validation enforces this contract so the taxonomy stays auditable.

All patterns are confidence=low at detection time. The pij baseline is
a regex tool; no regex match is high-confidence evidence of injection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


CATEGORIES: tuple[str, ...] = (
    "instruction_override",
    "role_manipulation",
    "system_prompt_extraction",
    "delimiter_injection",
    "encoded_payloads",
    "indirect_injection",
    "output_coercion",
)

# Categories excluded from the headline F1 number. Output coercion phrases
# overlap heavily with legitimate prompt engineering ("respond only with
# valid JSON"), so a headline that includes them would conflate two
# different things. Reported as a separate sub-metric.
HEADLINE_EXCLUDED_CATEGORIES: tuple[str, ...] = ("output_coercion",)

# Sentinel category for benign corpus rows that don't resemble any
# specific attack category (neutral controls). Accepted by the corpus
# validator but not iterated by per-category metric breakdowns.
NEUTRAL_CATEGORY = "neutral"

VALID_ROW_CATEGORIES: tuple[str, ...] = CATEGORIES + (NEUTRAL_CATEGORY,)

EXPECTED_FP_RATES: tuple[str, ...] = ("low", "medium", "high", "very high")


@dataclass(frozen=True)
class Pattern:
    id: str
    category: str
    regex: str
    description: str
    source: str
    expected_fp_rate: str
    notes: str = ""


PATTERNS: tuple[Pattern, ...] = (
    # ─── instruction_override ────────────────────────────────────────────
    Pattern(
        id="instruction_override_001",
        category="instruction_override",
        regex=r"(?i)\bignore\s+(?:all\s+|the\s+|any\s+|your\s+)?(?:previous|prior|preceding|above|earlier)\s+(?:instructions?|prompts?|rules?|commands?|directives?)\b",
        description="Canonical 'ignore previous instructions' override phrasing.",
        source="Perez & Ribeiro 2022, 'Ignore Previous Prompt: Attack Techniques For Language Models', arxiv.org/abs/2211.09527",
        expected_fp_rate="medium",
        notes="False-positives on quoted security writeups that discuss the attack itself.",
    ),
    Pattern(
        id="instruction_override_002",
        category="instruction_override",
        regex=r"(?i)\bdisregard\s+(?:all\s+|the\s+|any\s+|your\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|messages?|rules?)\b",
        description="'Disregard' variant of instruction override.",
        source="hand-crafted, paraphrase of common override phrasings observed in jailbreak corpora",
        expected_fp_rate="medium",
        notes="",
    ),
    Pattern(
        id="instruction_override_003",
        category="instruction_override",
        regex=r"(?i)\bforget\s+(?:everything|all|all\s+the)\s+(?:above|before|prior|previous|that\s+you\s+were\s+told)\b",
        description="'Forget everything above' variant.",
        source="hand-crafted",
        expected_fp_rate="medium",
        notes="",
    ),
    Pattern(
        id="instruction_override_004",
        category="instruction_override",
        regex=r"(?i)\boverride\s+(?:your|the|all)\s+(?:instructions?|safety|guidelines?|rules?|restrictions?)\b",
        description="Explicit 'override' phrasing.",
        source="hand-crafted",
        expected_fp_rate="low",
        notes="",
    ),
    # ─── role_manipulation ───────────────────────────────────────────────
    Pattern(
        id="role_manipulation_001",
        category="role_manipulation",
        regex=r"(?i)\bDAN\s+(?:mode|prompt|jailbreak)\b",
        description="Explicit DAN ('Do Anything Now') reference.",
        source="Shen et al. 2023, '\"Do Anything Now\": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models', arxiv.org/abs/2308.03825",
        expected_fp_rate="low",
        notes="",
    ),
    Pattern(
        id="role_manipulation_002",
        category="role_manipulation",
        regex=r"(?i)\byou\s+are\s+(?:now|going\s+to\s+be|hereby)\s+(?:DAN|an?\s+unrestricted|jailbroken|in\s+developer\s+mode|free\s+from)\b",
        description="Role-swap framing common to jailbreak prompts.",
        source="Shen et al. 2023, arxiv.org/abs/2308.03825",
        expected_fp_rate="medium",
        notes="",
    ),
    Pattern(
        id="role_manipulation_003",
        category="role_manipulation",
        regex=r"(?i)\b(?:act|pretend|behave)\s+as\s+(?:if\s+you\s+(?:were|are)\s+)?(?:an?\s+unrestricted|DAN|an?\s+evil|jailbroken|an?\s+AI\s+(?:without|with\s+no)\s+(?:restrictions?|filters?|rules?))\b",
        description="'Act as' or 'pretend to be' an unrestricted variant.",
        source="Shen et al. 2023, arxiv.org/abs/2308.03825",
        expected_fp_rate="medium",
        notes="",
    ),
    Pattern(
        id="role_manipulation_004",
        category="role_manipulation",
        regex=r"(?i)\bdeveloper\s+mode\s+(?:enabled|on|activated|please)\b",
        description="'Developer mode' role escalation.",
        source="hand-crafted, widely documented jailbreak idiom",
        expected_fp_rate="low",
        notes="",
    ),
    # ─── system_prompt_extraction ────────────────────────────────────────
    Pattern(
        id="system_prompt_extraction_001",
        category="system_prompt_extraction",
        regex=r"(?i)\b(?:repeat|print|reveal|show|display|output|tell\s+me)\s+(?:the\s+|your\s+|all\s+(?:of\s+)?)?(?:system\s+)?(?:instructions?|prompts?|guidelines?|rules?)\s+(?:above|before|that\s+you\s+were\s+given|verbatim|word\s+for\s+word)\b",
        description="Asking the model to repeat its system prompt.",
        source="Zhang & Ippolito 2023, 'Effective Prompt Extraction from Language Models', arxiv.org/abs/2307.06865",
        expected_fp_rate="medium",
        notes="",
    ),
    Pattern(
        id="system_prompt_extraction_002",
        category="system_prompt_extraction",
        regex=r"(?i)\bwhat\s+(?:is|are|were)\s+(?:your|the)\s+(?:system\s+|original\s+|initial\s+)?(?:instructions?|prompts?|guidelines?|rules?)\b",
        description="Asking 'what are your instructions'.",
        source="Zhang & Ippolito 2023, arxiv.org/abs/2307.06865",
        expected_fp_rate="medium",
        notes="False-positives on legitimate questions about a model's documented usage policy.",
    ),
    Pattern(
        id="system_prompt_extraction_003",
        category="system_prompt_extraction",
        regex=r"(?i)\b(?:print|show|repeat|output|display)\s+everything\s+(?:above|before\s+this|that\s+came\s+before|in\s+your\s+context)\b",
        description="'Print everything above' extraction.",
        source="hand-crafted",
        expected_fp_rate="low",
        notes="",
    ),
    # ─── delimiter_injection ─────────────────────────────────────────────
    Pattern(
        id="delimiter_injection_001",
        category="delimiter_injection",
        regex=r"<\|(?:system|im_start|im_end|user|assistant|endoftext)\|>",
        description="ChatML / OpenAI special tokens.",
        source="OpenAI ChatML format documentation (github.com/openai/openai-python historical chatml references)",
        expected_fp_rate="low",
        notes="Legitimate matches in documentation that quotes ChatML itself.",
    ),
    Pattern(
        id="delimiter_injection_002",
        category="delimiter_injection",
        regex=r"\[/?INST\]",
        description="Llama-2 instruction tags.",
        source="Meta AI, Llama-2 chat format documentation",
        expected_fp_rate="low",
        notes="",
    ),
    Pattern(
        id="delimiter_injection_003",
        category="delimiter_injection",
        regex=r"(?i)</?(?:system|assistant|user|human)>",
        description="XML-style fake chat-role tags.",
        source="hand-crafted; common in indirect injection payloads delivered via HTML/markdown",
        expected_fp_rate="medium",
        notes="False-positives on HTML/XML data that legitimately uses these tag names.",
    ),
    # ─── encoded_payloads ────────────────────────────────────────────────
    Pattern(
        id="encoded_payloads_001",
        category="encoded_payloads",
        regex=r"\b[A-Za-z0-9+/]{60,}={0,2}\b",
        description="Long base64-looking string (>=60 chars).",
        source="hand-crafted; covers naive base64-encoded payload delivery",
        expected_fp_rate="high",
        notes="Heavy false-positives on hashes, JWTs, API keys, and any legitimate base64 data.",
    ),
    Pattern(
        id="encoded_payloads_002",
        category="encoded_payloads",
        regex=r"[\U000E0000-\U000E007F]{3,}",
        description="Unicode tag-character covert channel (3+ chars).",
        source="OWASP LLM01:2025 obfuscation category; publicly documented Unicode tag covert channel technique",
        expected_fp_rate="low",
        notes="Tag characters are invisible to humans; matches are almost always intentional.",
    ),
    # ─── indirect_injection ──────────────────────────────────────────────
    Pattern(
        id="indirect_injection_001",
        category="indirect_injection",
        regex=r"(?i)\b(?:when|before|after|while)\s+(?:you\s+)?(?:summariz|analyz|process|read|see|encounter|review)\w*\s+this[^.!?\n]{0,80}\balso\b",
        description="'When you summarize this, also...' RAG/tool-output poisoning pattern.",
        source="Greshake et al. 2023, 'Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection', arxiv.org/abs/2302.12173",
        expected_fp_rate="medium",
        notes="",
    ),
    Pattern(
        id="indirect_injection_002",
        category="indirect_injection",
        regex=r"(?i)\b(?:important|urgent|new|critical|special)\s+(?:instructions?|message|note|directive)\s+(?:for|to)\s+the\s+(?:assistant|model|AI|LLM|language\s+model)\b",
        description="'Important instruction for the assistant' marker — typical of poisoned tool outputs.",
        source="Greshake et al. 2023, arxiv.org/abs/2302.12173",
        expected_fp_rate="medium",
        notes="",
    ),
    Pattern(
        id="indirect_injection_003",
        category="indirect_injection",
        regex=r"(?i)\bhidden\s+(?:instructions?|message|prompt|directive)(?:\s*:|\s+for\s+(?:the\s+)?(?:AI|assistant|model|LLM))",
        description="'Hidden instruction' marker — typical of HTML/markdown injection in retrieved content.",
        source="Greshake et al. 2023, arxiv.org/abs/2302.12173",
        expected_fp_rate="low",
        notes="",
    ),
    # ─── output_coercion ─────────────────────────────────────────────────
    # NOTE: All patterns in this category carry expected_fp_rate="very high".
    # Excluded from the headline F1 number; reported as a separate sub-metric.
    Pattern(
        id="output_coercion_001",
        category="output_coercion",
        regex=r"(?i)\brespond\s+only\s+with\b",
        description="'Respond only with' output coercion.",
        source="hand-crafted",
        expected_fp_rate="very high",
        notes="Routinely used in legitimate prompt engineering ('respond only with valid JSON'). Excluded from headline F1.",
    ),
    Pattern(
        id="output_coercion_002",
        category="output_coercion",
        regex=r"(?i)\bdo\s+not\s+(?:refuse|warn|caution|disclaim|apologize|hedge)\b",
        description="'Do not refuse/warn' suppression.",
        source="Shen et al. 2023, arxiv.org/abs/2308.03825",
        expected_fp_rate="very high",
        notes="Common in jailbreak prompts but also in legitimate role-play and creative-writing prompts. Excluded from headline F1.",
    ),
    Pattern(
        id="output_coercion_003",
        category="output_coercion",
        regex=r"(?i)\b(?:skip|omit|without)\s+(?:any\s+|all\s+)?(?:safety\s+)?(?:warnings?|disclaimers?|caveats?|hedging|qualifications?)\b",
        description="'Skip warnings/disclaimers' suppression.",
        source="hand-crafted",
        expected_fp_rate="very high",
        notes="Excluded from headline F1.",
    ),
)


def _validate_patterns() -> None:
    """Module-load validation: enforces the data contract."""
    seen_ids: set[str] = set()
    for p in PATTERNS:
        if p.id in seen_ids:
            raise ValueError(f"duplicate pattern id: {p.id}")
        seen_ids.add(p.id)
        if p.category not in CATEGORIES:
            raise ValueError(f"pattern {p.id}: unknown category {p.category!r}")
        if not p.source.strip():
            raise ValueError(f"pattern {p.id}: source field is required and non-empty")
        if p.expected_fp_rate not in EXPECTED_FP_RATES:
            raise ValueError(
                f"pattern {p.id}: expected_fp_rate must be one of {EXPECTED_FP_RATES}, "
                f"got {p.expected_fp_rate!r}"
            )
        try:
            re.compile(p.regex)
        except re.error as e:
            raise ValueError(f"pattern {p.id}: regex does not compile: {e}") from e
        if p.category in HEADLINE_EXCLUDED_CATEGORIES and p.expected_fp_rate != "very high":
            raise ValueError(
                f"pattern {p.id}: patterns in headline-excluded category "
                f"{p.category!r} must declare expected_fp_rate='very high'"
            )


_validate_patterns()


def patterns_by_category(category: str) -> tuple[Pattern, ...]:
    """Return all patterns belonging to the given category."""
    return tuple(p for p in PATTERNS if p.category == category)
