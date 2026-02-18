# Prompt Injection Detection with LLM Guard

## Table of Contents

- [Overview](#overview)
- [Security Context](#security-context-prompt-injection)
- [System Architecture](#system-architecture)
- [Running the Project](#running-the-project)
- [References](#references)


## Overview

This repository demonstrates input-level prompt injection detection using Protect AI’s `llm-guard` toolkit.

The project implements an input-boundary security filter that evaluates user prompts before they are passed to a generative Large Language Model (LLM). The system assigns a numeric risk score and produces an allow/block decision based on a configurable detection threshold.

This implementation is based on the taxonomy presented in the [`tldrsec/prompt-injection-defenses`](https://github.com/tldrsec/prompt-injection-defenses) repository and focuses specifically on detection-based mitigation rather than runtime guardrails or privilege isolation.


## Repository Includes

| Component | Description |
|------------|-------------|
| `demo.py` | Standalone Python implementation |
| `demo.ipynb` | Interactive Jupyter notebook version |
| `requirements.txt` | Reproducible dependency configuration |
| Virtual Environment | Clean dependency isolation |


## Intended Audience

- Students learning about LLM security  
- Engineers exploring prompt injection defenses  
- Researchers studying input-boundary filtering  
---

## Security Context: Prompt Injection

Prompt injection is a class of attacks in which adversarial instructions are embedded within user input or externally retrieved text in order to override system behavior.

Because Large Language Models process both instructions and data as natural language, malicious directives can be inserted into otherwise legitimate content.

### Common Attack Goals

- Override developer or system instructions  
- Extract hidden system prompts  
- Trigger unintended tool execution  
- Exfiltrate sensitive information  

> [!IMPORTANT]
> Detection at the input boundary reduces the likelihood that malicious instructions reach the generative model.
---

## System Architecture

This project implements an input-level detection layer using the `PromptInjection` scanner from `llm-guard`.

### Model Used

[`protectai/deberta-v3-base-prompt-injection-v2`](https://github.com/protectai/llm-guard)

The model analyzes the prompt and estimates the probability that it contains injection-style instructions.

---

### Scanner Output

The scanner returns:

```python
sanitized_prompt, is_valid, risk_score
```
| Return Value       | Description                                 |
| ------------------ | ------------------------------------------- |
| `sanitized_prompt` | Cleaned version of the input                |
| `is_valid`         | Boolean allow/block decision                |
| `risk_score`       | Numeric probability between `0.0` and `1.0` |

---

### Decision Logic

The detection threshold is configurable.

In this implementation:
```python
threshold = 0.5
```
Prompts with:

```python
risk_score >= 0.5
```
- They are classified as malicious and can be blocked before reaching the LLM.

- This separation between detection and generation reduces the attack surface of LLM-integrated applications.

---

## Running the Project

### Step 1 — Clone the Repository

```bash
git clone https://github.com/<your-username>/prompt-injection-defenses.git
cd prompt-injection-defenses
```
### Step 2 — Create a Virtual Environment
macOS / Linux:
```
python3 -m venv venv
source venv/bin/activate
```
Windows(Powershell)
```Windows(Powershell)
python -m venv venv
venv\Scripts\Activate.ps1
```
Windows (Command Prompt)
```Windows (Command Prompt)
python -m venv venv
venv\Scripts\activate
```
### Step 3 —  Install Dependencies
```bash
pip install -r requirements.txt
```
```bash
pip install "numpy<2"
```
> [!NOTE]
> `numpy` is pinned in `requirements.txt` to version `1.26.4` to maintain compatibility with PyTorch.


## Execution Options

### Option A - Run Basic Test 1 script (demo.py)
```bash
python3 demo.py
```
This version is suitable for quick terminal-based execution.

### Option B - Run Jupyter Comprehensive Notebook (demo.ipynb)

Open Jupyter
```bash
jupyter notebook
```
**Then open** 
```
demo.ipynb
```
>[!NOTE]
>This notebook includes Test 1 – Test 6 and provides step-by-step execution with printed results.

---

## Repository Structure

| File | Description |
|------|-------------|
| `demo.py` | Standalone script that runs prompt injection detection on predefined test prompts and prints results to the terminal. |
| `demo.ipynb` | Interactive notebook version of the detector that allows step-by-step execution and testing (includes Test 1–6). |
| `requirements.txt` | Lists the exact Python packages needed to run the project. |
| `.gitignore` | Prevents unnecessary local files from being uploaded to GitHub. |

---

## References

This implementation and Milestone 1 are informed by current academic and open-source work in LLM security, including:

1. tldrsec. *Prompt Injection Defenses.*  
   Available at: https://github.com/tldrsec/prompt-injection-defenses

2. Protect AI. *LLM Guard Toolkit.*  
   Available at: https://github.com/protectai/llm-guard

3. Gong, Neil. *Securing LLM Agents Against Prompt Injection Attacks.*  
   Duke University, 2025.  
   Available at: https://people.duke.edu/~zg70/code/PromptInjection.pdf


