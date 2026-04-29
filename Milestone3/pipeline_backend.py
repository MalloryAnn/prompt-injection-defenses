"""
Backend utilities for the prompt injection dashboard.

This version preserves the user's original contribution logic:
- Rebuff heuristic-only
- PromptInjection ML model
- Final decision = rb_flag OR pi_flag

It adds dashboard-friendly tracing without changing the original ensemble rule.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import json

import pandas as pd
from rebuff import RebuffSdk
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType


def initialize_systems() -> Dict[str, Any]:
    """
    Matches the notebook setup as closely as possible.
    """
    print("Initializing systems...")

    rb = RebuffSdk(
        "",   # no API key
        "",   # no vector DB
        "test-index",
        "gpt-3.5-turbo"
    )

    pi_scanner = PromptInjection(threshold=0.5, match_type=MatchType.FULL)

    print("Systems initialized ✅")
    return {
        "rb": rb,
        "pi_scanner": pi_scanner,
    }


def analyze_prompt(prompt: str, systems: Dict[str, Any]) -> Dict[str, Any]:
    """
    Preserves the original notebook logic and extends the returned data
    so the dashboard can explain each layer.
    """
    rb = systems["rb"]
    pi_scanner = systems["pi_scanner"]

    # --- Rebuff heuristic ---
    try:
        rb_result = rb.detect_injection(
            prompt,
            check_vector=False,
            check_llm=False,
            check_heuristic=True
        )
        rb_flag = bool(rb_result.injection_detected)
        rb_score = getattr(rb_result, "heuristic_score", None)
        if isinstance(rb_score, (int, float)):
            rb_score = round(float(rb_score), 2)
    except Exception as e:
        rb_result = None
        rb_flag = False
        rb_score = None
        rb_error = str(e)
    else:
        rb_error = None

    # --- PromptInjection ---
    sanitized_prompt, is_valid, pi_score = pi_scanner.scan(prompt)
    pi_flag = not bool(is_valid)
    pi_score = round(float(pi_score), 2)

    # ---final decision logic ---
    final_flag = rb_flag or pi_flag

    # --- updated dashboard metadata ---
    if rb_flag and pi_flag:
        decision_path = "Both Rebuff and PromptInjection flagged the prompt."
    elif rb_flag:
        decision_path = "Rebuff flagged the prompt; PromptInjection did not."
    elif pi_flag:
        decision_path = "PromptInjection flagged the prompt; Rebuff did not."
    else:
        decision_path = "Neither layer flagged the prompt."

    return {
        # original fields kept for continuity with the notebook
        "prompt": prompt,
        "rebuff_flag": rb_flag,
        "prompt_injection_flag": pi_flag,
        "pi_score": pi_score,
        "final_decision": final_flag,

        # extra fields for dashboard
        "rebuff_score": rb_score,
        "rebuff_error": rb_error,
        "sanitized_prompt": sanitized_prompt,
        "prompt_valid_after_scan": bool(is_valid),
        "decision_path": decision_path,
        "final_label": "Malicious / Flagged" if final_flag else "Safe / Allowed",

        # nested layer views for the architecture dashboard
        "layers": {
            "input": {
                "name": "Input Prompt Layer",
                "flag": False,
                "details": {
                    "prompt": prompt,
                    "description": "Raw prompt submitted into the pipeline."
                }
            },
            "rebuff": {
                "name": "Rebuff Heuristic Layer",
                "flag": rb_flag,
                "score": rb_score,
                "details": {
                    "mode": "heuristic-only",
                    "check_vector": False,
                    "check_llm": False,
                    "check_heuristic": True,
                    "error": rb_error,
                    "description": "Rule/heuristic-style first-pass detector."
                }
            },
            "prompt_injection": {
                "name": "PromptInjection ML Layer",
                "flag": pi_flag,
                "score": pi_score,
                "threshold": 0.5,
                "details": {
                    "is_valid": bool(is_valid),
                    "sanitized_prompt": sanitized_prompt,
                    "match_type": "FULL",
                    "description": "Model-based risk classifier from llm-guard."
                }
            },
            "orchestration": {
                "name": "Orchestration & Explainability Layer",
                "flag": final_flag,
                "details": {
                    "logic": "final_flag = rebuff_flag OR prompt_injection_flag",
                    "decision_path": decision_path,
                    "description": "Combines outputs from both detectors without changing the original ensemble logic."
                }
            },
            "final_decision": {
                "name": "Final Decision Layer",
                "flag": final_flag,
                "details": {
                    "label": "Malicious / Flagged" if final_flag else "Safe / Allowed",
                    "routing": "Stop and review" if final_flag else "Continue to LLM",
                    "description": "Final routing decision produced by the ensemble."
                }
            }
        }
    }


def load_prompts(file_path: str) -> List[str]:
    with open(file_path, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]


def run_batch(prompt_file: str = "prompts_1000.txt", output_csv: str = "contribution_results_1000.csv") -> pd.DataFrame:
    """
    Recreates the original notebook workflow:
    - load prompts
    - analyze prompts
    - save CSV
    - print summary
    """
    systems = initialize_systems()
    test_prompts = load_prompts(prompt_file)

    print(f"Loaded {len(test_prompts)} prompts")

    results = []
    for i, p in enumerate(test_prompts):
        result = analyze_prompt(p, systems)
        row = {k: v for k, v in result.items() if k != "layers"}
        results.append(row)

        if i % 50 == 0:
            print(f"Processed {i} prompts...")

    df = pd.DataFrame(results)
    df.to_csv(output_csv, index=False)

    print(f"Results saved to {output_csv}")
    print("Total prompts:", len(df))
    print("Flagged by Rebuff:", int(df["rebuff_flag"].sum()))
    print("Flagged by PromptInjection:", int(df["prompt_injection_flag"].sum()))
    print("Final flagged:", int(df["final_decision"].sum()))

    return df


def load_results_csv(csv_path: str = "contribution_results_1000.csv") -> pd.DataFrame:
    return pd.read_csv(csv_path)

def summarize_results(df: pd.DataFrame) -> Dict[str, int]:
    return {
        "total_prompts": int(len(df)),
        "flagged_by_rebuff": int(df["rebuff_flag"].sum()) if "rebuff_flag" in df else 0,
        "flagged_by_prompt_injection": int(df["prompt_injection_flag"].sum()) if "prompt_injection_flag" in df else 0,
        "final_flagged": int(df["final_decision"].sum()) if "final_decision" in df else 0,
    }
if __name__ == "__main__":
    run_batch("prompts_1000.txt", "contribution_results_1000.csv")