"""Phase 2 classifier calibration evaluation.

Measures how well P(malicious) scores correspond to actual malicious rates —
a prerequisite for the T-MDP's cost-optimal threshold to be meaningful.

Two test sets:
  in-distribution:   held-out fold from the full labeled OTRF corpus
  cross-technique:   events from 2 unseen-technique ZIPs (empire_uac, cmd_service_mod_fax)

Outputs a reliability table (predicted bucket vs actual rate), Expected
Calibration Error (ECE), Maximum Calibration Error (MCE), and Brier score.

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_calibration_eval.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import (
    _to_dataframe,
    build_classifier_pipeline,
    load_classifier,
    predict_proba_malicious,
)
from tmdp_sandbox.preprocessing import (
    auto_label_event,
    extract_features_for_sequence,
    load_otrf_dataset,
    load_otrf_labeled_pool,
)

REPO_ROOT = Path(__file__).parent.parent
MALICIOUS_DIR = REPO_ROOT / "data" / "raw" / "malicious"
MODEL_PATH = REPO_ROOT / "models" / "ml_classifier_logistic.joblib"
OUT_DIR = Path(__file__).parent / "calibration_eval"

TRAIN_ZIPS = [
    "cmd_stop_event_logging_controlset001_minint_key.zip",
    "cmd_stop_event_logging_controlset_minint_key.zip",
    "psh_stop_event_logging_controlset001_minint_key.zip",
    "psh_stop_event_logging_controlset_minint_key.zip",
    "reg_stop_event_logging_controlset001_minint_key.zip",
    "reg_stop_event_logging_controlset_minint_key.zip",
]
TEST_ZIPS = [
    "empire_uac_shellapi_fodhelper.zip",
    "cmd_service_mod_fax.zip",
]
N_BINS = 10


def _calibration_stats(scores: list[float], labels: list[int], n_bins: int = 10) -> dict:
    """Compute reliability table, ECE, MCE, and Brier score."""
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    bin_indices = np.digitize(scores, bins[1:-1])  # 0..n_bins-1

    table = []
    for b in range(n_bins):
        mask = bin_indices == b
        n = int(mask.sum())
        if n == 0:
            table.append({"bin_low": round(b / n_bins, 2),
                          "bin_high": round((b + 1) / n_bins, 2),
                          "n": 0, "mean_predicted": None, "actual_rate": None, "gap": None})
            continue
        mean_pred = float(np.array(scores)[mask].mean())
        actual = float(np.array(labels)[mask].mean())
        table.append({
            "bin_low": round(b / n_bins, 2),
            "bin_high": round((b + 1) / n_bins, 2),
            "n": n,
            "mean_predicted": round(mean_pred, 4),
            "actual_rate": round(actual, 4),
            "gap": round(abs(mean_pred - actual), 4),
        })

    total = len(scores)
    ece = float(sum(
        row["n"] / total * row["gap"]
        for row in table if row["n"] > 0
    ))
    mce = float(max((row["gap"] for row in table if row["n"] > 0), default=0.0))
    brier = float(np.mean((np.array(scores) - np.array(labels)) ** 2))

    return {"table": table, "ece": round(ece, 4), "mce": round(mce, 4), "brier": round(brier, 4)}


def _library_versions() -> dict:
    """Interpreter and library versions, recorded in results.json for reproducibility."""
    import platform
    from importlib.metadata import version

    return {
        "python": platform.python_version(),
        "scikit-learn": version("scikit-learn"),
        "numpy": version("numpy"),
        "pandas": version("pandas"),
        "joblib": version("joblib"),
    }


def _load_labeled_from_zips(zip_names: list[str]):
    import dataclasses
    events, labels = [], []
    for name in zip_names:
        path = MALICIOUS_DIR / name
        if not path.exists():
            continue
        for ev in load_otrf_dataset(path, label="malicious"):
            lbl = auto_label_event(ev)
            if lbl is not None:
                events.append(dataclasses.replace(ev, label=lbl))
                labels.append(lbl)
    return events, labels


def _format_table(rows: list[dict]) -> str:
    lines = [
        f"  {'Range':<12} {'n':>6} {'Pred':>8} {'Actual':>8} {'Gap':>8}",
        f"  {'-'*46}",
    ]
    for row in rows:
        if row["n"] == 0:
            lines.append(f"  [{row['bin_low']:.1f}–{row['bin_high']:.1f}]  {'':>6} {'(empty)':>8}")
            continue
        lines.append(
            f"  [{row['bin_low']:.1f}–{row['bin_high']:.1f}]"
            f"  {row['n']:>6}"
            f"  {row['mean_predicted']:>8.4f}"
            f"  {row['actual_rate']:>8.4f}"
            f"  {row['gap']:>8.4f}"
        )
    return "\n".join(lines)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    pipeline = load_classifier(MODEL_PATH)

    results = {"library_versions": _library_versions()}
    summary_lines = [
        "Phase 2 Classifier Calibration Evaluation",
        "=" * 60,
        "",
        "A perfectly calibrated classifier sits on the diagonal:",
        "P(malicious)=0.7 → 70% of events in that bucket are truly malicious.",
        "ECE (Expected Calibration Error): weighted mean |predicted − actual|.",
        "MCE (Maximum Calibration Error): worst-bucket gap.",
        "Brier score: mean squared error of probability estimates (lower = better).",
    ]

    # ── In-distribution: 5-fold CV held-out scores ─────────────────────────
    print("Loading all OTRF events for in-distribution calibration ...")
    benign_pool, malicious_pool = load_otrf_labeled_pool(MALICIOUS_DIR)
    all_events = benign_pool + malicious_pool
    import random
    random.Random(42).shuffle(all_events)
    feats, lbls = extract_features_for_sequence(all_events, window_size=10)
    binary = [1 if l == "malicious" else 0 for l in lbls]

    from sklearn.model_selection import StratifiedKFold
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    df = _to_dataframe(feats)
    y = np.array(binary)
    oof_scores = np.zeros(len(y))

    for train_idx, val_idx in skf.split(df, y):
        fold_pipeline = build_classifier_pipeline(model="logistic")
        fold_pipeline.fit(df.iloc[train_idx], y[train_idx])
        proba = fold_pipeline.predict_proba(df.iloc[val_idx])
        classes = list(fold_pipeline.classes_)
        mal_col = classes.index(1) if 1 in classes else -1
        oof_scores[val_idx] = proba[:, mal_col] if mal_col >= 0 else 0.0

    indist = _calibration_stats(oof_scores.tolist(), binary)
    results["in_distribution"] = indist
    summary_lines += [
        "",
        f"In-distribution (5-fold OOF, n={len(binary)}, "
        f"malicious={sum(binary)}, benign={len(binary)-sum(binary)}):",
        _format_table(indist["table"]),
        f"  ECE={indist['ece']:.4f}  MCE={indist['mce']:.4f}  Brier={indist['brier']:.4f}",
    ]

    # ── Cross-technique: unseen ZIPs ────────────────────────────────────────
    print("Loading cross-technique test events ...")
    test_events, test_lbls = _load_labeled_from_zips(TEST_ZIPS)
    if test_events:
        test_feats, test_labels = extract_features_for_sequence(test_events, window_size=10)
        test_binary = [1 if l == "malicious" else 0 for l in test_labels]
        test_scores = predict_proba_malicious(pipeline, test_feats)
        cross = _calibration_stats(test_scores, test_binary)
        results["cross_technique"] = cross
        summary_lines += [
            "",
            f"Cross-technique (empire_uac + cmd_service_mod_fax, n={len(test_binary)}, "
            f"malicious={sum(test_binary)}, benign={len(test_binary)-sum(test_binary)}):",
            _format_table(cross["table"]),
            f"  ECE={cross['ece']:.4f}  MCE={cross['mce']:.4f}  Brier={cross['brier']:.4f}",
        ]

    # ── Interpretation ──────────────────────────────────────────────────────
    summary_lines += [
        "",
        "Interpretation:",
        "  ECE < 0.05 is generally considered well-calibrated.",
        "  High concentration in 0.0-0.1 and 0.9-1.0 bins (near-binary output) is",
        "  expected given the perfect CV F1=1.000 (data/processed/train_stats.json).",
        "  It means the classifier is confident and correct within distribution,",
        "  but rarely produces scores in the 0.3-0.7 range where T-MDP and",
        "  threshold policies diverge.",
        "  The T-MDP block threshold p*=0.40 corresponds to a real probability only",
        "  if events in the (0.35, 0.45) bucket have ~40% actual malicious rate.",
    ]

    summary = "\n".join(summary_lines)
    print(f"\n{summary}")
    (OUT_DIR / "summary.txt").write_text(summary)
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))
    print(f"\nResults → {OUT_DIR}/")


if __name__ == "__main__":
    main()
