import sys
import os

sys.path.append(os.path.join(os.getcwd(), "vigil-llm/vigil"))

from rebuff import RebuffSdk
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType

# --- Initialize detectors ---

# Rebuff
rb = RebuffSdk(
    os.getenv("OPENAI_API_KEY"),
    "",
    "test-index",
    "gpt-3.5-turbo"
)

# PromptInjection
pi_scanner = PromptInjection(threshold=0.5, match_type=MatchType.FULL)


def analyze_prompt(prompt):
    # --- Rebuff ---
    try:
        rb_result = rb.detect_injection(prompt)
        rb_flag = rb_result.injection_detected
    except Exception as e:
        print("Rebuff skipped due to:", e)
        rb_flag = False

    # --- PromptInjection ---
    _, is_valid, pi_score = pi_scanner.scan(prompt)
    pi_flag = not is_valid

    # --- Final decision (ensemble logic) ---
    final_flag = rb_flag or pi_flag

    return {
        "prompt": prompt,
        "rebuff": rb_flag,
        "prompt_injection": pi_flag,
        "pi_score": pi_score,
        "final_decision": final_flag
    }


if __name__ == "__main__":
    print("=== Prompt Injection Detection System ===")
    print("Type 'exit' to quit\n")

    while True:
        user_prompt = input("Enter a prompt: ")

        if user_prompt.lower() == "exit":
            print("Exiting...")
            break

        result = analyze_prompt(user_prompt)
        print("\nResult:")
        print(result)
        print("-" * 50)
