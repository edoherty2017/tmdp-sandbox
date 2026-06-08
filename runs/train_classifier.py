"""Build and train the ML security classifier from downloaded datasets.

Labeling strategy (see preprocessing.auto_label_event for details):
  Benign:   EventID=1/4688 + known-good Windows process, no obfuscation
  Malicious: LOLBin process creation, lsass access (EID 10), persistence
             registry writes (EID 12/13), unsigned DLL loads (EID 7)

This produces same-format, same-source training data with meaningful class
separation. Windows_2k.log CBS entries are excluded (structurally incompatible).

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/train_classifier.py

Outputs:
    models/ml_classifier_logistic.joblib
    models/ml_classifier_forest.joblib
    data/processed/train_stats.json
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import (
    _to_dataframe,
    build_classifier_pipeline,
    predict_proba_malicious,
    save_classifier,
    train_classifier,
)
from tmdp_sandbox.preprocessing import (
    extract_features_for_sequence,
    load_otrf_labeled_pool,
)

REPO_ROOT = Path(__file__).parent.parent
MALICIOUS_DIR = REPO_ROOT / "data" / "raw" / "malicious"
MODELS_DIR = REPO_ROOT / "models"
PROCESSED_DIR = REPO_ROOT / "data" / "processed"


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    zip_files = sorted(MALICIOUS_DIR.glob("*.zip"))
    print(f"Loading and labeling events from {len(zip_files)} ZIPs ...")
    benign_events, malicious_events = load_otrf_labeled_pool(MALICIOUS_DIR)
    excluded = sum(1 for _ in ())  # load_otrf_labeled_pool discards ambiguous internally
    print(f"  Labeled malicious: {len(malicious_events)}")
    print(f"  Labeled benign:    {len(benign_events)}")

    if not benign_events:
        print("\nERROR: no benign events found — check _BASELINE_PROCESSES list")
        sys.exit(1)
    if not malicious_events:
        print("\nERROR: no malicious events found")
        sys.exit(1)

    # balance: cap malicious at 5× benign
    rng = random.Random(42)
    max_malicious = min(len(malicious_events), len(benign_events) * 5)
    if len(malicious_events) > max_malicious:
        malicious_events = rng.sample(malicious_events, max_malicious)
        print(f"\nDownsampled malicious to {max_malicious} (5× benign)")

    all_events = benign_events + malicious_events
    rng.shuffle(all_events)
    print(f"\nTotal training events: {len(all_events)}")

    print("Extracting features ...")
    feature_dicts, labels = extract_features_for_sequence(all_events, window_size=10)
    n_mal = sum(1 for l in labels if l == "malicious")
    n_ben = sum(1 for l in labels if l == "benign")
    print(f"  benign={n_ben}  malicious={n_mal}")

    print("\nRunning 5-fold stratified cross-validation ...")
    cv_stats = _cross_validate(feature_dicts, labels, model="logistic")
    print(f"  [logistic] CV  precision={cv_stats['precision']:.3f}±{cv_stats['prec_std']:.3f}  "
          f"recall={cv_stats['recall']:.3f}±{cv_stats['rec_std']:.3f}  "
          f"F1={cv_stats['f1']:.3f}±{cv_stats['f1_std']:.3f}")

    print("\nTraining logistic regression (full data) ...")
    lr_pipeline = train_classifier(feature_dicts, labels, model="logistic")
    lr_path = MODELS_DIR / "ml_classifier_logistic.joblib"
    save_classifier(lr_pipeline, lr_path)
    print(f"  Saved → {lr_path}")
    _print_threshold_stats(predict_proba_malicious(lr_pipeline, feature_dicts), labels, "logistic (in-sample)")

    print("\nTraining random forest (full data) ...")
    rf_pipeline = train_classifier(feature_dicts, labels, model="forest")
    rf_path = MODELS_DIR / "ml_classifier_forest.joblib"
    save_classifier(rf_pipeline, rf_path)
    print(f"  Saved → {rf_path}")
    _print_threshold_stats(predict_proba_malicious(rf_pipeline, feature_dicts), labels, "forest (in-sample)")

    stats = {
        "n_benign": n_ben,
        "n_malicious": n_mal,
        "n_total": len(labels),
        "malicious_zips": [zf.name for zf in zip_files],
        "cv_logistic": cv_stats,
        "labeling": "preprocessing.auto_label_event (EventID + process + obfuscation patterns)",
    }
    stats_path = PROCESSED_DIR / "train_stats.json"
    stats_path.write_text(json.dumps(stats, indent=2))
    print(f"\nStats → {stats_path}")
    print("\nDone.")


def _print_threshold_stats(scores: list[float], labels: list[str], model: str) -> None:
    tp = fp = tn = fn = 0
    for s, lbl in zip(scores, labels):
        pred = s >= 0.5
        actual = lbl == "malicious"
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    print(f"  [{model}] @0.5: precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}  "
          f"TP={tp} FP={fp} TN={tn} FN={fn}")


def _cross_validate(feature_dicts: list[dict], labels: list[str], *, model: str = "logistic", n_splits: int = 5) -> dict:
    from sklearn.model_selection import StratifiedKFold
    import numpy as np

    binary_labels = [1 if l == "malicious" else 0 for l in labels]
    df = _to_dataframe(feature_dicts)
    y = np.array(binary_labels)
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    precisions, recalls, f1s = [], [], []

    for train_idx, test_idx in skf.split(df, y):
        pipeline = build_classifier_pipeline(model=model)
        pipeline.fit(df.iloc[train_idx], y[train_idx])
        proba = pipeline.predict_proba(df.iloc[test_idx])
        classes = list(pipeline.classes_)
        mal_col = classes.index(1) if 1 in classes else -1
        preds = [1 if (mal_col >= 0 and row[mal_col] >= 0.5) else 0 for row in proba]
        y_test = y[test_idx]
        tp = sum(1 for p, a in zip(preds, y_test) if p == 1 and a == 1)
        fp = sum(1 for p, a in zip(preds, y_test) if p == 1 and a == 0)
        fn = sum(1 for p, a in zip(preds, y_test) if p == 0 and a == 1)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)

    return {
        "precision": float(np.mean(precisions)),
        "prec_std": float(np.std(precisions)),
        "recall": float(np.mean(recalls)),
        "rec_std": float(np.std(recalls)),
        "f1": float(np.mean(f1s)),
        "f1_std": float(np.std(f1s)),
        "n_splits": n_splits,
    }


if __name__ == "__main__":
    main()
