# Trustworthy AI Guardrails (Groq)

This project is a small, runnable demonstration of input and output guardrails
for a reference-grounded assistant. It uses the [Groq Python SDK](https://console.groq.com/docs/quickstart)
for generation and keeps the guardrails deterministic so they can be evaluated
without a network connection or API key.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export GROQ_API_KEY="..."
```

The model defaults to `llama-3.1-8b-instant`; override it with `GROQ_MODEL`.
Never commit a real key. `.env.example` documents the variables.

## Usage

```bash
python app.py "What are the library hours?" \
  --reference "The library is open from 9am to 5pm on weekdays. It is closed on public holidays."
```

The model is instructed to return JSON with `answer`, `citations`,
`risk_level`, and `refusal`. Missing/invalid output receives a safe fallback.
Input PII is redacted before the model call; prompt injection and high-risk
requests are blocked or routed to a cautious fallback.

## Guardrail design

| Stage | Detection | Action | Limitation |
|---|---|---|---|
| Input | Regex for email, phone, SSN, and common ID labels | Replace values with typed placeholders | Obfuscation, international formats, and novel identifiers can evade regexes |
| Input | Patterns for instruction overrides, prompt extraction, and role hijacking | Refuse | Paraphrases and multilingual attacks are not comprehensively detected |
| Input | Sensitive-topic patterns (self-harm, illegal harm, medical, legal/financial) | Refuse or review-style fallback | Keyword classification lacks context and can over-trigger |
| Output | Exact JSON shape, types, and enum validation | Safe fallback | A valid shape does not guarantee useful content |
| Output | Per-sentence lexical overlap with trusted reference | Safe fallback on unsupported claims | Word overlap is not semantic entailment and can miss subtle hallucinations |
| Output | Same PII detector, followed by redaction | Redact leaked values | Detection is incomplete; citations are not independently fetched |

Input controls run before Groq to avoid sending unnecessary PII or unsafe
requests. Output controls run after generation because model output is
untrusted even when the prompt requests a schema.

## Testing and evaluation

Run the 24-case offline suite:

```bash
pytest -q
python evaluate.py
```

`evaluate.py` writes `evaluation_results.json` with each test input ID,
expected label, actual label, and pass status. The tests cover normal queries,
PII, injections, sensitive topics, invalid schemas, leaked output PII, and
unsupported claims.

The evaluation set contains ground-truth labels for detector behavior. Report
precision and recall as:

```text
precision = true positives / (true positives + false positives)
recall    = true positives / (true positives + false negatives)
```

These are a small hand-authored smoke set, not evidence of production-level
accuracy. See [REPORT.md](REPORT.md) for the recorded results, failure cases,
trade-offs, and deployment assessment.

## Architecture

The diagram is in [architecture.mmd](architecture.mmd). It can be rendered by
Mermaid-compatible tooling.
