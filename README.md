# Prompt Injection Guardrail System

## Table of Contents

- [Overview](#overview)
- [Implemented Tools Explained](#implemented-tools-explained)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Running the Project](#running-the-project)
- [Workflow](#workflow)
- [Key Design](#key-design)
- [Summary](#summary)
- [References](#references)


## Overview

The Prompt Injection Guardrail system is a multi-layered detection system that combines Rebuff (heurisitic-based detection) and PromptInjection (machine learning-based detection). The system is designed to detect and measure performance of prompts in large language model workflows then provide visualized results through an interactive dashboard. 

Each prompt is analyzed by a unified analysis function that processes prompts through both detectors, and the system uses an ensemble decision rule, where a prompt is flagged if either detection layer identifies it as potential malicious input.  


## Implemented Tools Explained

1. Rebuff - A rule-based detection approach designed to identify common patterns found in prompt injection attacks. It works by scanning prompts for suspicious structures such as:
   - Instructions that attempt to override system behavior
   - Requests to reveal hidden or sensitive information
   - Role manipulation

2. PromptInjection - A machine learning-based classifier that analyzes prompts to detect potentially malicious, or manipulative inputs. It relies on learned patterns from labeled data, which allows it to:
   - Detect subtle or previously unseen injection attempts
   - Generalize better new attack strategies
   - Capture context and intent beyond simple keywords


## Project Structure

| Component | Description |
|------------|-------------|
| `prompts.py` | Generates labeled prompt dataset |
| `pipeline_backend.py` | Runs detection pipeline |
| `evalutation.py` | Computes performance metrics |
| `dashboard.py` | Interactive dashboard (visualization) |
| `prompts_1000.txt` | Raw prompts |
| `prompts_1000_labeled.csv` | Prompts with ground-truth labels |
| `contribution_results_1000.csv` | Detection results | 


## Setup

Install required dependences:
pip install -r requirements.txt


## Running the Project

### Step 1 — Generate Labeled Prompts

```bash
cd prompt-injection-defenses-main/Milestone3
python3 prompts.py
```
This creates the dataset and corresponding labels

### Step 2 — Run Detection Pipeline
```bash
python3 pipeline_backend.py
```
Processes all prompts using both detection layers and saves results

### Step 3 —  Run Evaluation
```bash
python3 evaluation.py
```
Computes: 
- Accuracy
- Precision
- Recall
- F1 Score
- Error rates

### Optional Shortcut 
You can skip the first 3 steps and run step 4, if using saved file that is already included in main 'dashboard.py' code. 

### Step 4 - Launch Dashboard
```bash
python3 dashboard.py
```

**Then open in your browser:** 
```
http://127.0.0.1:8050/
```


## Workflow
prompts → detection pipeline → results csv → evaluation → dashboard

1. Prompts represents a dataset of benign, borderline, and malicious prompts.
2. Detection Pipeline processes prompts through Rebuff and PromptInjection.
3. Results csv is a produced file containing detection results and evaluation metrics.
4. Evaluation computes accuracy, precision, recall, F1 score, and error rates.
5. Dashboard is a provided visualization of the analyzation results. 

## Key Design
The system uses an ensemble approach that combines rule-based detection with a machine learning classifier. 

### Decision Rule 
```bash
final_flag = rebuff_flag OR prompt_injection_flag  
```
A prompt is flagged as malicious if either component detects it. This approach prioritizes catching as many attacks as possible. 

Evaluation is performed using labeled prompt data as ground truth to ensure unbiased metrics. The dashboard provides visualization of detection decisions, system architecture, and performance analysis.

## Summary
This project demonstrates a multi-layer defense system against prompt injection attacks in large language models, combining rule-based heuristics with a machine learning classifier. 
The system includes a full pipeline for dataset generation, detection, evaluation, and an interactive dashboard for analyzing model performance and failure cases. 


## References


1. tldrsec. *Prompt Injection Defenses.*  
   Available at: https://github.com/tldrsec/prompt-injection-defenses

2. Protect AI. *LLM Guard Toolkit.*  
   Available at: https://github.com/protectai/llm-guard

3. Gong, Neil. *Securing LLM Agents Against Prompt Injection Attacks.*  
   Duke University, 2025.  
   Available at: https://people.duke.edu/~zg70/code/PromptInjection.pdf


