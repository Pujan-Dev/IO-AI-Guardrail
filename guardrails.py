"""Input and output guardrails for a small grounded AI assistant.

The guardrails are intentionally deterministic so they can be tested without an
API key. Groq is used by the application adapter, not by these pure functions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

Action = Literal["allow", "redact", "refuse", "review"]


@dataclass(frozen=True)
class Finding:
    guardrail: str
    category: str
    evidence: str
    action: Action


@dataclass(frozen=True)
class InputDecision:
    allowed: bool
    sanitized_text: str
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class OutputDecision:
    valid: bool
    response: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)


PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "phone": re.compile(
        r"(?<!\w)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-])\d{3}[\s.-]\d{4}(?!\w)"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "national_id": re.compile(r"(?i)\b(?:national\s+id|citizenship|passport)\s*[:#-]?\s*[A-Z0-9-]{6,}\b"),
}

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,80}\b("
        r"previous|system|developer|instructions?|rules?|safety)\b", re.I | re.S)),
    ("prompt_extraction", re.compile(
        r"\b(show|reveal|print|repeat|tell me|leak|expose)\b.{0,80}\b("
        r"system prompt|hidden prompt|secret|confidential|api key|instructions?)\b", re.I | re.S)),
    ("role_hijack", re.compile(
        r"\b(you are now|act as|pretend to be)\b.{0,50}\b("
        r"unrestricted|developer|admin|jailbreak|dan)\b", re.I)),
)

SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str], Action], ...] = (
    ("self_harm", re.compile(r"\b(kill myself|suicide|self[- ]harm|end my life)\b", re.I), "refuse"),
    ("illegal_harm", re.compile(
        r"\b(make|build|buy|deploy).{0,50}\b(bomb|weapon|malware|ransomware|poison)\b", re.I | re.S), "refuse"),
    ("medical", re.compile(r"\b(diagnose|symptoms?|medication dosage|medical advice)\b", re.I), "review"),
    ("legal_financial", re.compile(
        r"\b(legal advice|lawsuit|tax evasion|guaranteed investment|buy stocks)\b", re.I), "review"),
)

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")


def detect_pii(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for category, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append(Finding("pii", category, match.group(0), "redact"))
    return findings


def redact_pii(text: str) -> str:
    redacted = text
    for category, pattern in PII_PATTERNS.items():
        redacted = pattern.sub(f"[REDACTED_{category.upper()}]", redacted)
    return redacted


def detect_prompt_injection(text: str) -> list[Finding]:
    return [
        Finding("prompt_injection", category, match.group(0), "refuse")
        for category, pattern in INJECTION_PATTERNS
        if (match := pattern.search(text))
    ]


def classify_sensitive_topic(text: str) -> list[Finding]:
    return [
        Finding("sensitive_topic", category, match.group(0), action)
        for category, pattern, action in SENSITIVE_PATTERNS
        if (match := pattern.search(text))
    ]


def inspect_input(text: str) -> InputDecision:
    """Redact PII, refuse injection, and route high-risk topics for review."""
    findings = detect_pii(text) + detect_prompt_injection(text) + classify_sensitive_topic(text)
    if any(f.action == "refuse" for f in findings):
        return InputDecision(False, redact_pii(text), findings)
    return InputDecision(True, redact_pii(text), findings)


REQUIRED_FIELDS = {"answer", "citations", "risk_level", "refusal"}
RISK_LEVELS = {"low", "medium", "high"}


def validate_schema(response: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(response, dict):
        return [Finding("schema", "not_object", "response is not an object", "refuse")]
    missing = REQUIRED_FIELDS - response.keys()
    if missing:
        findings.append(Finding("schema", "missing_fields", ", ".join(sorted(missing)), "refuse"))
    if not isinstance(response.get("answer"), str):
        findings.append(Finding("schema", "answer_type", "answer must be a string", "refuse"))
    if not isinstance(response.get("citations"), list) or not all(
        isinstance(item, str) for item in response.get("citations", [])
    ):
        findings.append(Finding("schema", "citations_type", "citations must be a list of strings", "refuse"))
    if response.get("risk_level") not in RISK_LEVELS:
        findings.append(Finding("schema", "risk_level_value", "risk_level is not low, medium, or high", "refuse"))
    if not isinstance(response.get("refusal"), bool):
        findings.append(Finding("schema", "refusal_type", "refusal must be boolean", "refuse"))
    return findings


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


def validate_groundedness(answer: str, reference: str, minimum_overlap: float = 0.35) -> list[Finding]:
    """Require each non-trivial sentence to share terms with the reference.

    This is a conservative lexical heuristic, not a proof of factual entailment.
    """
    findings: list[Finding] = []
    reference_tokens = _tokens(reference)
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", answer) if _tokens(s)]
    for sentence in sentences:
        sentence_tokens = _tokens(sentence)
        overlap = len(sentence_tokens & reference_tokens) / max(len(sentence_tokens), 1)
        if len(sentence_tokens) < 2 or overlap < minimum_overlap:
            findings.append(Finding("groundedness", "unsupported_claim", sentence, "refuse"))
    return findings


def inspect_output(response: Any, reference: str) -> OutputDecision:
    """Validate shape, source support, and redact any leaked sensitive data."""
    schema_findings = validate_schema(response)
    if schema_findings:
        return OutputDecision(False, safe_fallback("I could not produce a response in the required format."), schema_findings)

    output = dict(response)
    pii_findings = detect_pii(output["answer"])
    if pii_findings:
        output["answer"] = redact_pii(output["answer"])
    grounding_findings = validate_groundedness(output["answer"], reference)
    findings = pii_findings + grounding_findings
    if grounding_findings:
        return OutputDecision(False, safe_fallback("I cannot verify that claim from the provided reference."), findings)
    return OutputDecision(True, output, findings)


def safe_fallback(message: str) -> dict[str, Any]:
    return {
        "answer": message,
        "citations": [],
        "risk_level": "low",
        "refusal": True,
    }


def finding_categories(findings: list[Finding]) -> set[str]:
    return {f.category for f in findings}
