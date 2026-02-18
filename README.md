# Prompt Injection Detection with LLM Guard

This repository demonstrates input-level prompt injection detection using Protect AI’s `llm-guard` toolkit.

The project implements an input-boundary security filter that evaluates user prompts before they are passed to a generative Large Language Model (LLM). The system assigns a numeric risk score and produces an allow/block decision based on a configurable detection threshold.

This implementation is based on the taxonomy presented in the `tldrsec/prompt-injection-defenses` repository and focuses specifically on detection-based mitigation rather than runtime guardrails or privilege isolation.

The repository includes:

- A standalone Python implementation (`demo.py`)
- An interactive Jupyter notebook (`demo.ipynb`)
- Reproducible environment configuration (`requirements.txt`)
- A clean dependency isolation setup using a virtual environment

This project is suitable for:

- Students learning about LLM security
- Engineers exploring prompt injection defenses
- Researchers studying input-boundary filtering


---

## Security Context: Prompt Injection

Prompt injection is a class of attacks in which adversarial instructions are embedded within user input or externally retrieved text in order to override system behavior.

Because Large Language Models process both instructions and data as natural language, malicious directives can be inserted into otherwise legitimate content. These attacks may attempt to:

- Override developer or system instructions
- Extract hidden system prompts
- Trigger unintended tool execution
- Exfiltrate sensitive information

Detection at the input boundary reduces the likelihood that malicious instructions reach the generative model.

---

## System Architecture

This project implements an input-level detection layer using the `PromptInjection` scanner from `llm-guard`.

### Input
Raw prompt text supplied by a user or external source.

### Processing
The scanner loads a transformer-based classification model:

**protectai/deberta-v3-base-prompt-injection-v2**

The model analyzes the prompt and estimates the probability that it contains injection-style instructions.

The scanner returns:

```python
sanitized_prompt, is_valid, risk_score
```
- sanitized_prompt – cleaned version of the input

- is_valid – Boolean allow/block decision

- risk_score – numeric probability between 0.0 and 1.0

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

### 1. Clone Repository

``` bash
git clone https://github.com/<your-username>/prompt-injection-defenses.git
cd prompt-injection-defenses
---
```
### 2. Create Virtual Environment

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
### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
```bash
pip install "numpy<2"
```
### 4. Execution Options
Run Basic Test 1 script
```bash
python3 demo.py
```
This version is suitable for quick terminal-based execution.

**Or**  


### Run Jupyter Comprehensive Notebook

Open Jupyter and run the notebook that has test 1 - 6
```bash
jupyter notebook
```
**Then open** 
```
demo.ipynb
```
**Comprehensive File Descriptions**
**`demo.py`**  
Standalone Python implementation of the prompt injection detector.  
Runs detection on predefined test prompts and prints:

- Prompt text
- Allow/block decision
- Risk score

This version is suitable for quick terminal-based execution.

---

**`demo.ipynb`**  
Interactive notebook version of the same implementation.  
Provides:

- Step-by-step execution
- Visible model initialization logs
- Printed detection results
- Suitable format for demonstration and experimentation

This version is recommended for educational use and walkthroughs.

---

**`requirements.txt`**  
Fully reproducible dependency list generated from the working virtual environment.  
Allows other users to recreate the exact runtime configuration.

---

**`.gitignore`**  
Prevents local development files (e.g., virtual environments, IDE configuration files, notebook checkpoints) from being committed to the repository.






