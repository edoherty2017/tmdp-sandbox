"""Cross-technique generalization evaluation.

Trains the Phase 2 classifier on 6 OTRF ZIPs (stop-event-logging variants using
cmd, psh, and reg tools) and evaluates on 2 held-out ZIPs representing unseen
attack techniques:
  - empire_uac_shellapi_fodhelper.zip (UAC bypass via fodhelper.exe)
  - cmd_service_mod_fax.zip (Fax service binary-path modification)

This tests whether F1=0.997 CV performance is real generalization or memorization
of process names seen during training.

Output: runs/cross_technique_eval/
    results.json   — per-event predictions on test set
    summary.txt    — precision/recall/F1, confusion matrix

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_cross_technique_eval.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import (
    _to_dataframe,
    build_classifier_pipeline,
    predict_proba_malicious,
    save_classifier,
)
from tmdp_sandbox.preprocessing import (
    auto_label_event,
    extract_features_for_sequence,
    load_otrf_dataset,
    load_otrf_labeled_pool,
)

REPO_ROOT = Path(__file__).parent.parent
MALICIOUS_DIR = REPO_ROOT / "data" / "raw" / "malicious"
OUT_DIR = Path(__file__).parent / "cross_technique_eval"

# 6 training ZIPs: stop-event-logging, three tools × two control-set variants
TRAIN_ZIPS = [
    "cmd_stop_event_logging_controlset001_minint_key.zip",
    "cmd_stop_event_logging_controlset_minint_key.zip",
    "psh_stop_event_logging_controlset001_minint_key.zip",
    "psh_stop_event_logging_controlset_minint_key.zip",
    "reg_stop_event_logging_controlset001_minint_key.zip",
    "reg_stop_event_logging_controlset_minint_key.zip",
]

# 2 test ZIPs: unseen attack techniques
TEST_ZIPS = [
    "empire_uac_shellapi_fodhelper.zip",
    "cmd_service_mod_fax.zip",
]


def _load_labeled_from_zips(zip_names: list[str]) -> tuple[list, list]:
    """Load and auto-label events from specific ZIPs.  Returns (events, labels)."""
    import dataclasses

    events, labels = [], []
    for name in zip_names:
        path = MALICIOUS_DIR / name
        if not path.exists():
            print(f"  WARNING: {name} not found, skipping")
            continue
        raw_events = load_otrf_dataset(path, label="malicious")
        for event in raw_events:
            lbl = auto_label_event(event)
            if lbl is None:
                continue
            labeled = dataclasses.replace(event, label=lbl)
            events.append(labeled)
            labels.append(lbl)
    return events, labels


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


def _precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Train ──────────────────────────────────────────────────────────────
    print("Loading TRAIN ZIPs (6 stop-event-logging variants) ...")
    train_events, train_labels = _load_labeled_from_zips(TRAIN_ZIPS)
    n_train_mal = train_labels.count("malicious")
    n_train_ben = train_labels.count("benign")
    print(f"  Train events: {len(train_events)}  (benign={n_train_ben}, malicious={n_train_mal})")

    if not train_events:
        print("ERROR: no train events labeled")
        sys.exit(1)

    print("\nExtracting train features ...")
    train_feats, train_lbls = extract_features_for_sequence(train_events, window_size=10)

    print("Training logistic regression pipeline ...")
    pipeline = build_classifier_pipeline(model="logistic")
    import numpy as np
    df_train = _to_dataframe(train_feats)
    y_train = np.array([1 if l == "malicious" else 0 for l in train_lbls])
    pipeline.fit(df_train, y_train)

    in_sample_scores = predict_proba_malicious(pipeline, train_feats)
    tp = fp = tn = fn = 0
    for s, l in zip(in_sample_scores, train_lbls):
        pred = s >= 0.5
        actual = l == "malicious"
        if pred and actual: tp += 1
        elif pred: fp += 1
        elif actual: fn += 1
        else: tn += 1
    prec, rec, f1 = _precision_recall_f1(tp, fp, fn)
    print(f"  In-sample @0.5: precision={prec:.3f} recall={rec:.3f} F1={f1:.3f}  "
          f"TP={tp} FP={fp} TN={tn} FN={fn}")

    # ── Test ───────────────────────────────────────────────────────────────
    print("\nLoading TEST ZIPs (2 unseen techniques) ...")
    test_events, test_labels = _load_labeled_from_zips(TEST_ZIPS)
    n_test_mal = test_labels.count("malicious")
    n_test_ben = test_labels.count("benign")
    print(f"  Test events: {len(test_events)}  (benign={n_test_ben}, malicious={n_test_mal})")

    if not test_events:
        print("ERROR: no test events labeled — check auto_label_event coverage for these ZIPs")
        sys.exit(1)

    print("\nExtracting test features ...")
    test_feats, test_lbls = extract_features_for_sequence(test_events, window_size=10)

    print("Scoring test events ...")
    test_scores = predict_proba_malicious(pipeline, test_feats)

    per_zip_stats: dict[str, dict] = {}
    global_tp = global_fp = global_tn = global_fn = 0
    per_event_rows = []

    for zip_name in TEST_ZIPS:
        import dataclasses
        path = MALICIOUS_DIR / zip_name
        if not path.exists():
            continue
        raw = load_otrf_dataset(path, label="malicious")
        zip_events = []
        for ev in raw:
            lbl = auto_label_event(ev)
            if lbl is not None:
                zip_events.append(dataclasses.replace(ev, label=lbl))

        if not zip_events:
            per_zip_stats[zip_name] = {"n": 0}
            continue

        feats, lbls = extract_features_for_sequence(zip_events, window_size=10)
        scores = predict_proba_malicious(pipeline, feats)
        tp = fp = tn = fn = 0
        for s, l in zip(scores, lbls):
            pred = s >= 0.5
            actual = l == "malicious"
            if pred and actual: tp += 1
            elif pred: fp += 1
            elif actual: fn += 1
            else: tn += 1
        prec, rec, f1 = _precision_recall_f1(tp, fp, fn)
        per_zip_stats[zip_name] = {
            "n": len(lbls),
            "n_malicious": lbls.count("malicious"),
            "n_benign": lbls.count("benign"),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        }
        global_tp += tp; global_fp += fp; global_tn += tn; global_fn += fn

    g_prec, g_rec, g_f1 = _precision_recall_f1(global_tp, global_fp, global_tn + global_fn - global_tn)
    g_prec, g_rec, g_f1 = _precision_recall_f1(global_tp, global_fp, global_fn)

    # Calibration: fraction of events where predicted score > 0.5 that were truly malicious
    mal_scores = [s for s, l in zip(test_scores, test_lbls) if l == "malicious"]
    ben_scores = [s for s, l in zip(test_scores, test_lbls) if l == "benign"]

    summary_lines = [
        "Cross-Technique Generalization Evaluation",
        "=" * 60,
        f"Train: {', '.join(z.replace('.zip','') for z in TRAIN_ZIPS)}",
        f"  Events: {len(train_events)} (benign={n_train_ben}, malicious={n_train_mal})",
        "",
        f"Test:  {', '.join(z.replace('.zip','') for z in TEST_ZIPS)}",
        f"  Events: {len(test_events)} (benign={n_test_ben}, malicious={n_test_mal})",
        "",
        "Per-ZIP results (test set):",
    ]
    for zname, stats in per_zip_stats.items():
        if stats.get("n", 0) == 0:
            summary_lines.append(f"  {zname}: no labeled events")
            continue
        summary_lines.append(
            f"  {zname}:"
            f"  n={stats['n']} (ben={stats['n_benign']}, mal={stats['n_malicious']})"
            f"  precision={stats['precision']:.3f}  recall={stats['recall']:.3f}  F1={stats['f1']:.3f}"
            f"  TP={stats['tp']} FP={stats['fp']} TN={stats['tn']} FN={stats['fn']}"
        )
    summary_lines += [
        "",
        "Overall test set:",
        f"  precision={g_prec:.3f}  recall={g_rec:.3f}  F1={g_f1:.3f}",
        f"  TP={global_tp}  FP={global_fp}  TN={global_tn}  FN={global_fn}",
        "",
        "Score distribution (test set):",
        f"  Malicious events (n={len(mal_scores)}): "
        f"mean={sum(mal_scores)/len(mal_scores):.3f}" if mal_scores else "  Malicious events: none",
        f"  Benign events   (n={len(ben_scores)}): "
        f"mean={sum(ben_scores)/len(ben_scores):.3f}" if ben_scores else "  Benign events: none",
        "",
        "In-sample (train, for reference):",
        f"  precision={prec:.3f}  recall={rec:.3f}  F1={f1:.3f}",
    ]

    summary = "\n".join(summary_lines)
    print(f"\n{summary}")
    (OUT_DIR / "summary.txt").write_text(summary)

    results = {
        "library_versions": _library_versions(),
        "train_zips": TRAIN_ZIPS,
        "test_zips": TEST_ZIPS,
        "train_stats": {"n": len(train_events), "n_benign": n_train_ben, "n_malicious": n_train_mal},
        "test_stats": {"n": len(test_events), "n_benign": n_test_ben, "n_malicious": n_test_mal},
        "in_sample": {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)},
        "overall_test": {"precision": round(g_prec, 4), "recall": round(g_rec, 4), "f1": round(g_f1, 4),
                         "tp": global_tp, "fp": global_fp, "tn": global_tn, "fn": global_fn},
        "per_zip": per_zip_stats,
        "score_distribution": {
            "malicious_mean": round(sum(mal_scores) / len(mal_scores), 4) if mal_scores else None,
            "benign_mean": round(sum(ben_scores) / len(ben_scores), 4) if ben_scores else None,
        },
    }
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))
    print(f"\nResults → {OUT_DIR}/")


if __name__ == "__main__":
    main()
