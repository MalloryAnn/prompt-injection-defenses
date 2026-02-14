# prompt-injection-defenses

Reference survey repo:
https://github.com/tldrsec/prompt-injection-defenses

---

## Current Focus – Milestone 1

Goal:
- Run an approved prompt injection defense tool
- Demonstrate input → processing → output
- Explain what problem it solves
- Start drafting milestone paper

We chose: **LLM Guard – Prompt Injection Scanner**

Reason:
- Easiest to install and test locally
- Real trained model
- Clear risk scoring output
- Good starting point before implementing blast radius reduction + guardrails

---

## Why Prompt Injection Matters

Prompt injection allows malicious users to:
- Override system instructions
- Reveal hidden prompts
- Trigger unintended tool usage
- Exfiltrate secrets

LLMs follow natural language instructions probabilistically, so injection attacks exploit that behavior.

Milestone 1 = input-level detection defense.

---

## Implementation Notes

Environment:
- Python venv
- numpy downgraded to 1.26.4 (torch compatibility issue)
- Model downloaded automatically (DeBERTa-based classifier)

Main file:
- `demo.py`
- `Milestone1_LLM_Guard_Demo.ipynb`

Test Prompts Used:
1. Benign summarization request
2. System prompt extraction attempt
3. Developer mode + secret exfil attempt

Observed:
- Benign prompt → VALID True, low risk
- Injection prompts → VALID False, high risk (1.0)

---

## What This Tool Actually Does

Input:
- Raw prompt text

Processing:
- Transformer classifier (`protectai/deberta-v3-base-prompt-injection-v2`)
- Calculates injection probability score

Output:
- Boolean validity (True/False)
- Risk score (0.0–1.0)

Threshold currently set to 0.5.

---

## Future Direction

Next Milestone Considerations:
- Start with blast radius reduction (limit tool access)
- Add guardrails / action guards
- Possibly simulate tool misuse scenario
- Compare detection-only vs defense-in-depth approach

---

## Paper Sections To Write

Must include:

- Project Overview
- Security Problem Addressed
- Architecture & Workflow
- LLM Usage (model, prompts, threshold)
- Strengths & Limitations
- Reproducibility Notes

Target length: 4–6 pages (PDF)

---

## Reminders

- Use provided datasets or small test cases.
- Keep environment reproducible.
- Screenshot terminal outputs.
- Document threshold experiments.
