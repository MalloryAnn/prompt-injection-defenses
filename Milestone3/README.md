# Prompt Injection Guardrail System

## Overview
This project implements a multi-layer prompt injection detection system using Rebuff (heuristic-based detection) and PromptInjection (machine learning-based detection). The system evaluates prompts, measures performance, and visualizes results through an interactive dashboard. The final decision is based on an ensemble rule that flags a prompt if either detection layer identifies risk.

## Project Structure
Milestone3/
- prompts.py → generates labeled prompt dataset  
- pipeline_backend.py → runs detection pipeline  
- evaluation.py → computes performance metrics  
- dashboard.py → interactive dashboard  
- prompts_1000.txt → raw prompts  
- prompts_1000_labeled.csv → prompts with true labels  
- contribution_results_1000.csv → detection results  

## Setup
Install required dependencies:
pip install -r requirements.txt

## How to Run

Step 1: Generate labeled prompts  
python3 prompts.py  
This creates the prompt dataset and corresponding labels.

Step 2: Run detection pipeline  
python3 pipeline_backend.py  
This processes all prompts using Rebuff and PromptInjection and saves the results.

Step 3: Run evaluation  
python3 evaluation.py  
This computes performance metrics including accuracy, precision, recall, F1 score, and error rates.

#or you can skip everything above and just run this, if you want to use my saved file that is already included in main dashboard.py code.

Step 4: Launch dashboard  
python3 dashboard.py  
Then open the application in a browser at:  
http://127.0.0.1:8050/

## Workflow
prompts → detection pipeline → results csv → evaluation → dashboard

## Key Design
The system uses an ensemble rule:  
final_flag = rebuff_flag OR prompt_injection_flag  

Evaluation is performed using labeled prompt data as ground truth to ensure unbiased metrics. The dashboard provides visualization of detection decisions, system architecture, and performance analysis.

## Summary
This project demonstrates a complete prompt injection defense system including detection, evaluation, and explainable visualization.