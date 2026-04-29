# evaluation.py
import pandas as pd

CSV_PATH = "contribution_results_1000.csv"
LABELS_PATH = "prompts_1000_labeled.csv"
ML_THRESHOLD = 0.50
BORDERLINE_LOW = 0.30

# assign risk level based on ml score
def risk_band(score):
    if pd.isna(score):
        return "not scored"

    score = float(score)

    if score >= ML_THRESHOLD:
        return "high"
    if BORDERLINE_LOW <= score < ML_THRESHOLD:
        return "borderline"
    return "low"

# load results and merge w/true results
def load_eval_data(csv_path=CSV_PATH):
    df = pd.read_csv(csv_path)
    labels = pd.read_csv(LABELS_PATH)

    for col in ["rebuff_flag", "prompt_injection_flag", "final_decision"]:
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().map({
                "true": True,
                "false": False,
                "1": True,
                "0": False
            }).fillna(False)

    df = df.merge(labels, on="prompt", how="left")

    df["prompt_category"] = df["true_label"]

    df["true_binary"] = df["true_label"].apply(
        lambda x: 1 if x == "malicious" else 0
    )

    df["predicted"] = df["final_decision"].astype(int)

    if "pi_score" in df.columns:
        df["pi_score"] = pd.to_numeric(df["pi_score"], errors="coerce").fillna(0)
        df["risk_band"] = df["pi_score"].apply(risk_band)
    else:
        df["pi_score"] = 0
        df["risk_band"] = "not scored"

    return df

# compute confusion matrix values
def confusion_counts(df):
    TP = ((df["true_binary"] == 1) & (df["predicted"] == 1)).sum()
    TN = ((df["true_binary"] == 0) & (df["predicted"] == 0)).sum()
    FP = ((df["true_binary"] == 0) & (df["predicted"] == 1)).sum()
    FN = ((df["true_binary"] == 1) & (df["predicted"] == 0)).sum()

    return {
        "TP": int(TP),
        "TN": int(TN),
        "FP": int(FP),
        "FN": int(FN)
    }
# safe division to avoid divide by zero
def safe_divide(a, b):
    return a / b if b else 0

#calc performance metrics
def get_metrics(csv_path=CSV_PATH):
    df = load_eval_data(csv_path)
    counts = confusion_counts(df)

    TP = counts["TP"]
    TN = counts["TN"]
    FP = counts["FP"]
    FN = counts["FN"]

    accuracy = safe_divide(TP + TN, len(df))
    precision = safe_divide(TP, TP + FP)
    recall = safe_divide(TP, TP + FN)
    f1 = safe_divide(2 * precision * recall, precision + recall)

    false_positive_rate = safe_divide(FP, FP + TN)
    false_negative_rate = safe_divide(FN, FN + TP)

    return {
        "total_prompts": int(len(df)),
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2),
        "false_positive_rate": round(false_positive_rate * 100, 2),
        "false_negative_rate": round(false_negative_rate * 100, 2),
        **counts
    }

#breakdown of results by category
def category_breakdown(csv_path=CSV_PATH):
    df = load_eval_data(csv_path)

    breakdown = (
        df.groupby("prompt_category")
        .agg(
            total=("prompt", "count"),
            flagged=("final_decision", "sum"),
            avg_ml_score=("pi_score", "mean"),
            rebuff_flags=("rebuff_flag", "sum"),
            ml_flags=("prompt_injection_flag", "sum")
        )
        .reset_index()
    )

    breakdown["flag_rate"] = (
        breakdown["flagged"] / breakdown["total"] * 100
    ).round(2)

    breakdown["avg_ml_score"] = breakdown["avg_ml_score"].round(3)

    return breakdown

# compare detector behavior overlap
def detector_overlap(csv_path=CSV_PATH):
    df = load_eval_data(csv_path)

    both = ((df["rebuff_flag"] == True) & (df["prompt_injection_flag"] == True)).sum()
    rebuff_only = ((df["rebuff_flag"] == True) & (df["prompt_injection_flag"] == False)).sum()
    ml_only = ((df["rebuff_flag"] == False) & (df["prompt_injection_flag"] == True)).sum()
    neither = ((df["rebuff_flag"] == False) & (df["prompt_injection_flag"] == False)).sum()

    return {
        "both_detectors_flagged": int(both),
        "rebuff_only": int(rebuff_only),
        "ml_only": int(ml_only),
        "neither_flagged": int(neither)
    }

#analyze results by risk score band
def risk_band_breakdown(csv_path=CSV_PATH):
    df = load_eval_data(csv_path)

    risk_df = (
        df.groupby("risk_band")
        .agg(
            total=("prompt", "count"),
            flagged=("final_decision", "sum"),
            avg_score=("pi_score", "mean")
        )
        .reset_index()
    )

    risk_df["flag_rate"] = (risk_df["flagged"] / risk_df["total"] * 100).round(2)
    risk_df["avg_score"] = risk_df["avg_score"].round(3)

    return risk_df

# get exmaples of model errors
def error_examples(csv_path=CSV_PATH, limit=5):
    df = load_eval_data(csv_path)

    false_positives = df[
        (df["true_binary"] == 0) & (df["predicted"] == 1)
    ][["prompt_category", "prompt", "pi_score", "rebuff_flag", "prompt_injection_flag"]].head(limit)

    false_negatives = df[
        (df["true_binary"] == 1) & (df["predicted"] == 0)
    ][["prompt_category", "prompt", "pi_score", "rebuff_flag", "prompt_injection_flag"]].head(limit)

    return false_positives, false_negatives

#run full evaluation pipeline
def get_full_analysis(csv_path=CSV_PATH):
    return {
        "metrics": get_metrics(csv_path),
        "category_breakdown": category_breakdown(csv_path),
        "detector_overlap": detector_overlap(csv_path),
        "risk_band_breakdown": risk_band_breakdown(),
    }

#main execution for testing
if __name__ == "__main__":
    print("\n=== Overall Metrics ===")
    print(get_metrics())

    print("\n=== Category Breakdown ===")
    print(category_breakdown())

    print("\n=== Detector Overlap ===")
    print(detector_overlap())

    print("\n=== Risk Band Breakdown ===")
    print(risk_band_breakdown())

    print("\n=== Error Examples ===")
    fp, fn = error_examples(limit=25)

    print("\nFalse Positives:")
    print(fp)

    print("\nFalse Negatives:")
    print(fn)
