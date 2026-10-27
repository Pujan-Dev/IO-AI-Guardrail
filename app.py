"""Groq-backed CLI application with input and output guardrails."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from guardrails import inspect_input, inspect_output, safe_fallback


SYSTEM_PROMPT = """You are a careful reference-grounded assistant.
Return ONLY valid JSON with exactly these fields:
{"answer": string, "citations": [string], "risk_level": "low|medium|high", "refusal": boolean}
Use only the supplied reference. If it does not support an answer, refuse.
Do not include personal data."""


def generate_with_groq(question: str, reference: str) -> dict[str, Any]:
    """Call Groq lazily so offline guardrail tests do not need the dependency."""
    try:
        from groq import Groq
    except ImportError as exc:
        raise RuntimeError("Install requirements.txt to use the Groq adapter.") from exc
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    completion = client.chat.completions.create(
        model=os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"),
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Reference:\n{reference}\n\nQuestion:\n{question}"},
        ],
    )
    content = completion.choices[0].message.content
    if not content:
        raise RuntimeError("Groq returned an empty response.")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Groq returned invalid JSON.") from exc
    return parsed


def answer(question: str, reference: str, generator=generate_with_groq) -> dict[str, Any]:
    decision = inspect_input(question)
    if not decision.allowed:
        return safe_fallback("I cannot help with that request.")
    if any(f.action == "review" for f in decision.findings):
        return safe_fallback("This topic needs qualified human guidance; I cannot provide a definitive answer.")
    if not os.environ.get("GROQ_API_KEY"):
        return safe_fallback("Set GROQ_API_KEY to enable the Groq-backed assistant.")
    raw = generator(decision.sanitized_text, reference)
    return inspect_output(raw, reference).response


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the guarded Groq assistant.")
    parser.add_argument("question")
    parser.add_argument("--reference", required=True, help="Trusted reference text.")
    args = parser.parse_args()
    print(json.dumps(answer(args.question, args.reference), indent=2))


if __name__ == "__main__":
    main()
