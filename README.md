## LLM Guard - Prompt Injection Scanner

Reason for Selection:
- Straightforward local installation
- Uses a trained transformer-based classifier
- Produces interpretable risk scoring output
- Provides a practical starting point before implementing blast radius reduction and additional safeguards

---

## Why Prompt Injection Matters

Prompt injection enables adversarial users to:
- Override system or developer instructions
- Reveal hidden system prompts
- Trigger unintended tool execution
- Exfiltrate sensitive information

Because large language models interpret both instructions and data as natural language, attackers can embed malicious directives within otherwise legitimate content. Detection at the input boundary reduces the likelihood of unsafe model behavior.

Milestone 1 focuses on input-level detection.

---

## Implementation Notes

Environment:
- Python virtual environment (venv)
- NumPy pinned below version 2.0 (Torch compatibility)
- Model automatically downloaded on first execution

Primary Files:
- `demo.py`
- `Milestone1_LLM_Guard_Demo.ipynb`

Test Prompts Evaluated:
1. Benign summarization request  
2. System prompt extraction attempt  
3. Developer mode with secret exfiltration attempt  

Observed Behavior:
- Benign prompt → `VALID: True`, low risk score  
- Injection attempts → `VALID: False`, high risk score (approaching 1.0)

---

## What This Tool Does

Input:
- Raw prompt text

Processing:
- Transformer-based classification model  
  (`protectai/deberta-v3-base-prompt-injection-v2`)
- Computes injection probability score

Output:
- Boolean validity classification (`True` or `False`)
- Numeric risk score (range: 0.0–1.0)

Decision Threshold:
- Currently set to `0.5`

Prompts with scores ≥ 0.5 are classified as malicious.

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
### 4. Execute Detection Script
Run the standalone script
```bash
python3 demo.ipynb
```
**Or**

Open Jupyter and run the notebook
```bash
jupyter notebook
```
**Then open** 
```
demo.ipynb
```




