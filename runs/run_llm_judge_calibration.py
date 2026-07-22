"""LLM-judge calibration experiment: turn the report's assertion into a measurement.

Report section 4.5 justifies dropping the LLM judge with the claim that
"LLM-generated confidence numbers are not calibrated" — asserted, never
measured. This script measures it: a stratified sample of ~542 events is
scored by the shared LLM judge (src/tmdp_sandbox/llm_judge.py, Claude Code CLI
transport on the project subscription) AND by the deployed classifier
(models/ml_classifier_logistic.joblib), and both are evaluated side by side
with the SAME 10 reliability bins as runs/run_calibration_eval.py.

Event sample (seeded random.Random(42), deterministic order — a --limit N
smoke run scores a prefix of the full plan, so cached responses carry over):

  a. train_pool    120 malicious + 120 benign events sampled from the
                   auto-labeled OTRF pool over data/raw/malicious (same event
                   set as preprocessing.load_otrf_labeled_pool, verified at
                   runtime; labels = auto_label_event). CIRCULAR for the
                   classifier (it was trained on these labels), independent
                   for the LLM judge.
  b. hard_benign   ALL 152 hand-authored benign admin events, imported from
                   runs/run_hard_benign_eval.py (corpus-order context).
  c. eval_holdout  150 events from the large independent eval's labeled
                   corpus (runs/run_large_independent_eval.py load_and_label,
                   labels = label_by_technique), stratified by
                   (technique, label).

Each event is scored ONCE by the judge with its real k=10 preceding context
window (ZIP recorded order for a/c; authored corpus order for b — matching
the "context stream" variant of the hard-benign eval). Judge responses are
cached at runs/llm_judge_calibration/responses.jsonl (JSONL keyed by
sha256(model + "\\x00" + prompt)), so interrupted runs resume for free; the
exact prompt for every event is logged to prompts.jsonl under the same key.

Metrics per subset and overall, LLM judge vs classifier:
  - reliability table (10 bins, identical to run_calibration_eval.py),
    ECE / MCE / Brier
  - score-distribution histogram counts + mass in the 0.1-0.9 "desert"
    (bins [0.1,0.9)) where the near-binary classifier places almost nothing
  - FP rate at p* = 0.40 / 0.50 on the hard-benign subset, Wilson 95% CIs
  - refusal / parse-failure counts (p=None: recorded and counted, never
    fabricated; excluded from metric computation)

Usage:
    cd tmdp-sandbox
    python runs/run_llm_judge_calibration.py [--limit N] [--concurrency 4] \\
        [--model claude-opus-4-8]

Outputs:
    runs/llm_judge_calibration/responses.jsonl  — judge response cache (append-only)
    runs/llm_judge_calibration/prompts.jsonl    — exact prompt per scored event
    runs/llm_judge_calibration/results.json     — metrics, per-event scores, metadata
    runs/llm_judge_calibration/summary.txt      — human-readable report
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from itertools import zip_longest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))  # sibling run_* imports

from tmdp_sandbox.classifier import MLCommandClassifier
from tmdp_sandbox.event_spec import EventSpec
from tmdp_sandbox.llm_judge import DEFAULT_MODEL, LLMJudge
from tmdp_sandbox.preprocessing import (
    auto_label_event,
    load_otrf_dataset,
    load_otrf_labeled_pool,
)

# Reuse (not duplicate) the sibling experiments' artifacts and helpers.
from run_hard_benign_eval import CORPUS as HARD_BENIGN_CORPUS
from run_hard_benign_eval import _fp_block, _library_versions
from run_large_independent_eval import load_and_label

REPO_ROOT = Path(__file__).parent.parent
MALICIOUS_DIR = REPO_ROOT / "data" / "raw" / "malicious"
MODEL_PATH = REPO_ROOT / "models" / "ml_classifier_logistic.joblib"
OUT_DIR = Path(__file__).parent / "llm_judge_calibration"
CACHE_PATH = OUT_DIR / "responses.jsonl"
PROMPTS_PATH = OUT_DIR / "prompts.jsonl"

SEED = 42
WINDOW_SIZE = 10
N_BINS = 10                      # SAME bins as runs/run_calibration_eval.py
THRESHOLDS = (0.40, 0.50)
N_TRAIN_PER_CLASS = 120
N_EVAL_SAMPLE = 150
SUBSETS = ("train_pool", "hard_benign", "eval_holdout")


# ---------------------------------------------------------------------------
# Sampling (seeded, stratified, deterministic order)
# ---------------------------------------------------------------------------

def _make_item(
    uid: str,
    subset: str,
    label_str: str,
    seq: tuple[EventSpec, ...],
    idx: int,
    meta: dict,
) -> dict:
    return {
        "uid": uid,
        "subset": subset,
        "label": 1 if label_str == "malicious" else 0,
        "event": seq[idx],
        "seq": seq,
        "idx": idx,
        "meta": meta,
    }


def _judge_context(item: dict) -> list[EventSpec]:
    """Real k=10 preceding events in the item's source sequence order."""
    return list(item["seq"][max(0, item["idx"] - WINDOW_SIZE): item["idx"]])


def _load_train_candidates() -> tuple[list[dict], dict[str, tuple[EventSpec, ...]]]:
    """Auto-labeled training pool with (zip, index) retained.

    Same iteration and labeling as preprocessing.load_otrf_labeled_pool
    (sorted ZIPs, auto_label_event, ambiguous discarded) — reconstructed here
    only because the pool loader drops the positional information needed for
    real k=10 context windows. main() verifies the counts against
    load_otrf_labeled_pool at runtime.
    """
    sequences: dict[str, tuple[EventSpec, ...]] = {}
    candidates: list[dict] = []
    for zf in sorted(MALICIOUS_DIR.glob("*.zip")):
        events = tuple(load_otrf_dataset(zf, label="malicious"))
        sequences[zf.name] = events
        for i, event in enumerate(events):
            lbl = auto_label_event(event)
            if lbl is not None:
                candidates.append({"zip": zf.name, "idx": i, "label": lbl})
    return candidates, sequences


def _sample_train_items(rng: random.Random, limit: int | None) -> tuple[list[dict], dict]:
    candidates, sequences = _load_train_candidates()
    mal = [c for c in candidates if c["label"] == "malicious"]
    ben = [c for c in candidates if c["label"] == "benign"]
    pool_counts = {"malicious": len(mal), "benign": len(ben)}

    mal_sample = rng.sample(mal, min(N_TRAIN_PER_CLASS, len(mal)))
    ben_sample = rng.sample(ben, min(N_TRAIN_PER_CLASS, len(ben)))
    # Interleave classes so a --limit prefix still contains both.
    ordered = [
        c
        for pair in zip_longest(mal_sample, ben_sample)
        for c in pair
        if c is not None
    ]
    if limit is not None:
        ordered = ordered[:limit]

    items = [
        _make_item(
            uid=f"train-{n:04d}",
            subset="train_pool",
            label_str=c["label"],
            seq=sequences[c["zip"]],
            idx=c["idx"],
            meta={"zip": c["zip"], "event_idx": c["idx"]},
        )
        for n, c in enumerate(ordered)
    ]
    return items, pool_counts


def _hard_benign_items(limit: int | None) -> list[dict]:
    events = tuple(
        EventSpec(
            process_name=entry["process_name"],
            command_line=entry["command_line"],
            user_name=entry["user_name"],
            parent_process=entry["parent_process"],
            event_id=entry["event_id"],
            label="benign",
        )
        for entry in HARD_BENIGN_CORPUS
    )
    n = len(events) if limit is None else min(limit, len(events))
    return [
        _make_item(
            uid=f"hard-{i:04d}",
            subset="hard_benign",
            label_str="benign",
            seq=events,
            idx=i,
            meta={"category": HARD_BENIGN_CORPUS[i]["category"], "corpus_idx": i},
        )
        for i in range(n)
    ]


def _stratified_allocation(sizes: dict, total: int) -> dict:
    """Proportional largest-deficit allocation, >=1 per non-empty stratum."""
    keys = sorted(sizes)
    n_all = sum(sizes.values())
    if total >= n_all:
        return dict(sizes)
    if len(keys) >= total:
        return {k: (1 if i < total else 0) for i, k in enumerate(keys)}
    alloc = {k: 1 for k in keys}
    desired = {k: sizes[k] * total / n_all for k in keys}
    for _ in range(total - len(keys)):
        eligible = [k for k in keys if alloc[k] < sizes[k]]
        best = max(eligible, key=lambda k: (desired[k] - alloc[k], sizes[k], k))
        alloc[best] += 1
    return alloc


def _sample_eval_items(rng: random.Random, limit: int | None) -> tuple[list[dict], dict]:
    labeled, load_stats, sequences = load_and_label()

    strata: dict[tuple[str, str], list[dict]] = {}
    for entry in labeled:  # load_and_label order is deterministic
        strata.setdefault((entry["technique"], entry["ground_truth"]), []).append(entry)

    alloc = _stratified_allocation({k: len(v) for k, v in strata.items()}, N_EVAL_SAMPLE)
    sampled: dict[tuple[str, str], list[dict]] = {
        k: rng.sample(strata[k], alloc[k]) for k in sorted(strata)
    }
    # Round-robin across strata so a --limit prefix spans several strata.
    ordered: list[dict] = []
    queues = {k: list(v) for k, v in sampled.items()}
    while any(queues.values()):
        for k in sorted(queues):
            if queues[k]:
                ordered.append(queues[k].pop(0))
    if limit is not None:
        ordered = ordered[:limit]

    items = [
        _make_item(
            uid=f"eval-{n:04d}",
            subset="eval_holdout",
            label_str=entry["ground_truth"],
            seq=sequences[entry["source_zip"]],
            idx=entry["event_idx"],
            meta={
                "zip": entry["source_zip"],
                "event_idx": entry["event_idx"],
                "technique": entry["technique"],
                "tactic": entry["tactic"],
            },
        )
        for n, entry in enumerate(ordered)
    ]
    strata_counts = {f"{t}/{lbl}": len(v) for (t, lbl), v in sorted(strata.items())}
    return items, {"corpus_size": len(labeled), "strata": strata_counts}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_llm(judge: LLMJudge, items: list[dict], concurrency: int) -> dict[str, object]:
    """Score every item once via the judge; progress every ~20 events."""
    results: dict[str, object] = {}
    total = len(items)
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(judge.score_event, item["event"], _judge_context(item)): item["uid"]
            for item in items
        }
        done = 0
        for future in as_completed(futures):
            results[futures[future]] = future.result()
            done += 1
            if done % 20 == 0 or done == total:
                cached = sum(1 for r in results.values() if r.cached)
                null = sum(1 for r in results.values() if r.p_malicious is None)
                print(f"  [{done}/{total}] LLM-judged (cached={cached}, null={null})")
    return results


def _score_classifier(classifier: MLCommandClassifier, items: list[dict]) -> dict[str, float]:
    return {
        item["uid"]: classifier.score_event(item["event"], item["seq"], item["idx"])
        for item in items
    }


# ---------------------------------------------------------------------------
# Metrics (bins identical to runs/run_calibration_eval.py)
# ---------------------------------------------------------------------------

def _calibration_stats(scores: list[float], labels: list[int], n_bins: int = N_BINS) -> dict | None:
    """Reliability table, ECE, MCE, Brier — same binning as run_calibration_eval."""
    if not scores:
        return None
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
    ece = float(sum(row["n"] / total * row["gap"] for row in table if row["n"] > 0))
    mce = float(max((row["gap"] for row in table if row["n"] > 0), default=0.0))
    brier = float(np.mean((np.array(scores) - np.array(labels)) ** 2))
    return {"table": table, "ece": round(ece, 4), "mce": round(mce, 4), "brier": round(brier, 4)}


def _hist_block(scores: list[float]) -> dict | None:
    """Histogram counts over the same 10 bins + mass in the 0.1-0.9 desert."""
    if not scores:
        return None
    bins = np.linspace(0.0, 1.0, N_BINS + 1)
    idx = np.digitize(scores, bins[1:-1])
    counts = [int((idx == b).sum()) for b in range(N_BINS)]
    desert = sum(counts[1:9])  # bins [0.1,0.2) .. [0.8,0.9)
    return {
        "n": len(scores),
        "bin_counts": counts,
        "desert_mass_0.1_0.9": round(desert / len(scores), 4),
    }


def _scorer_block(scores: list[float], labels: list[int]) -> dict | None:
    if not scores:
        return None
    return {
        "n": len(scores),
        "calibration": _calibration_stats(scores, labels),
        "histogram": _hist_block(scores),
    }


def _subset_metrics(rows: list[dict]) -> dict:
    llm_valid = [r for r in rows if r["llm_p"] is not None]
    block = {
        "n": len(rows),
        "n_malicious": sum(r["label"] for r in rows),
        "n_benign": sum(1 - r["label"] for r in rows),
        "llm_null_count": len(rows) - len(llm_valid),
        "llm_cached_count": sum(1 for r in rows if r["llm_cached"]),
        "llm_judge": _scorer_block(
            [r["llm_p"] for r in llm_valid], [r["label"] for r in llm_valid]
        ),
        "classifier": _scorer_block(
            [r["classifier_p"] for r in rows], [r["label"] for r in rows]
        ),
    }
    if block["llm_null_count"] > 0:
        # Strict head-to-head: classifier restricted to LLM-scored events.
        block["classifier_matched_to_llm_valid"] = _scorer_block(
            [r["classifier_p"] for r in llm_valid], [r["label"] for r in llm_valid]
        )
    return block


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _format_table(rows: list[dict]) -> str:
    lines = [
        f"    {'Range':<12} {'n':>6} {'Pred':>8} {'Actual':>8} {'Gap':>8}",
        f"    {'-'*46}",
    ]
    for row in rows:
        if row["n"] == 0:
            lines.append(f"    [{row['bin_low']:.1f}–{row['bin_high']:.1f}]  {'':>6} {'(empty)':>8}")
            continue
        lines.append(
            f"    [{row['bin_low']:.1f}–{row['bin_high']:.1f}]"
            f"  {row['n']:>6}"
            f"  {row['mean_predicted']:>8.4f}"
            f"  {row['actual_rate']:>8.4f}"
            f"  {row['gap']:>8.4f}"
        )
    return "\n".join(lines)


def _format_scorer(name: str, block: dict | None) -> list[str]:
    if block is None:
        return [f"  {name}: no scored events"]
    cal = block["calibration"]
    hist = block["histogram"]
    return [
        f"  {name} (n={block['n']}):",
        _format_table(cal["table"]),
        f"    ECE={cal['ece']:.4f}  MCE={cal['mce']:.4f}  Brier={cal['brier']:.4f}",
        f"    histogram counts: {hist['bin_counts']}",
        f"    mass in 0.1–0.9 desert: {hist['desert_mass_0.1_0.9']*100:.1f}%",
    ]


def _format_fp_line(label: str, block: dict) -> str:
    lo, hi = block["wilson_95ci"]
    return (
        f"  {label:<28} FP {block['fp']:>3}/{block['n']}"
        f" = {block['fp_rate']*100:6.1f}%  (95% Wilson CI {lo*100:.1f}–{hi*100:.1f}%)"
    )


def _claude_cli_version(claude_bin: str = "claude") -> str:
    try:
        proc = subprocess.run(
            [claude_bin, "--version"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
        )
        return (proc.stdout or proc.stderr).strip() or f"exit {proc.returncode}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=None,
                        help="cap events per subset (smoke runs; prefix of the full plan)")
    parser.add_argument("--concurrency", type=int, default=4,
                        help="parallel CLI calls (clamped to 1..5)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"judge model id (default {DEFAULT_MODEL})")
    args = parser.parse_args()
    concurrency = max(1, min(5, args.concurrency))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)

    # ── Build the deterministic event plan ─────────────────────────────────
    print("Sampling subset a: auto-labeled training pool ...")
    train_items, pool_counts = _sample_train_items(rng, args.limit)
    print(f"  pool: {pool_counts['malicious']} malicious / {pool_counts['benign']} benign "
          f"-> sampled {len(train_items)}")

    # Runtime verification that the reconstruction matches the canonical pool.
    benign_pool, malicious_pool = load_otrf_labeled_pool(MALICIOUS_DIR)
    if (len(malicious_pool), len(benign_pool)) != (pool_counts["malicious"], pool_counts["benign"]):
        raise RuntimeError(
            f"train-pool reconstruction diverged from load_otrf_labeled_pool: "
            f"{pool_counts} vs malicious={len(malicious_pool)}, benign={len(benign_pool)}"
        )

    print("Building subset b: hard-benign corpus ...")
    hard_items = _hard_benign_items(args.limit)
    print(f"  corpus: {len(HARD_BENIGN_CORPUS)} events -> scoring {len(hard_items)}")

    print("Sampling subset c: large independent eval corpus (labels first) ...")
    eval_items, eval_info = _sample_eval_items(rng, args.limit)
    print(f"  corpus: {eval_info['corpus_size']} labeled events -> sampled {len(eval_items)}")

    items = train_items + hard_items + eval_items
    print(f"Total events to score: {len(items)}")

    # ── Log exact prompts, then score ──────────────────────────────────────
    judge = LLMJudge(model=args.model, cache_path=CACHE_PATH)
    with PROMPTS_PATH.open("w", encoding="utf-8") as fh:
        for item in items:
            prompt = judge.build_event_prompt(item["event"], _judge_context(item))
            key = hashlib.sha256(f"{judge.model}\x00{prompt}".encode("utf-8")).hexdigest()
            fh.write(json.dumps({
                "uid": item["uid"],
                "subset": item["subset"],
                "prompt_sha256": key,
                "prompt": prompt,
            }) + "\n")
    print(f"Prompts logged -> {PROMPTS_PATH}")

    print(f"Scoring with LLM judge (model={args.model}, concurrency={concurrency}) ...")
    llm_results = _score_llm(judge, items, concurrency)

    print("Scoring with deployed classifier ...")
    classifier = MLCommandClassifier.from_file(MODEL_PATH, window_size=WINDOW_SIZE)
    clf_scores = _score_classifier(classifier, items)

    # ── Per-event records ──────────────────────────────────────────────────
    per_event = []
    for item in items:
        jr = llm_results[item["uid"]]
        per_event.append({
            "uid": item["uid"],
            "subset": item["subset"],
            "label": item["label"],
            "event_id": item["event"].event_id,
            "process_name": item["event"].process_name,
            "command_line": (item["event"].command_line or "")[:200],
            "llm_p": jr.p_malicious,
            "llm_cached": jr.cached,
            "llm_rationale": (jr.rationale or "")[:200],
            "prompt_sha256": jr.prompt_sha256,
            "classifier_p": round(clf_scores[item["uid"]], 6),
            "meta": item["meta"],
        })

    # ── Metrics ────────────────────────────────────────────────────────────
    metrics = {
        name: _subset_metrics([r for r in per_event if r["subset"] == name])
        for name in SUBSETS
    }
    metrics["overall"] = _subset_metrics(per_event)

    hb_rows = [r for r in per_event if r["subset"] == "hard_benign"]
    hb_llm = [r["llm_p"] for r in hb_rows if r["llm_p"] is not None]
    hb_clf = [r["classifier_p"] for r in hb_rows]
    hard_benign_fp = {
        "llm_judge": [_fp_block(hb_llm, t) for t in THRESHOLDS] if hb_llm else None,
        "classifier": [_fp_block(hb_clf, t) for t in THRESHOLDS] if hb_clf else None,
    }

    # ── Results + provenance ───────────────────────────────────────────────
    results = {
        "metadata": {
            "date": date.today().isoformat(),
            "model": args.model,
            "claude_cli_version": _claude_cli_version(judge.claude_bin),
            "seed": SEED,
            "window_size": WINDOW_SIZE,
            "n_bins": N_BINS,
            "thresholds": list(THRESHOLDS),
            "concurrency": concurrency,
            "limit": args.limit,
            "sample_sizes": {
                "train_pool": {"requested": 2 * N_TRAIN_PER_CLASS, "actual": len(train_items),
                               "pool": pool_counts},
                "hard_benign": {"requested": len(HARD_BENIGN_CORPUS), "actual": len(hard_items)},
                "eval_holdout": {"requested": N_EVAL_SAMPLE, "actual": len(eval_items),
                                 "corpus_size": eval_info["corpus_size"]},
                "total": len(items),
            },
            "eval_strata": eval_info["strata"],
            "library_versions": _library_versions(),
            "classifier_model": str(MODEL_PATH.relative_to(REPO_ROOT)),
        },
        "provenance": {
            "purpose": (
                "Converts report section 4.5's asserted justification for dropping "
                "the LLM judge ('LLM-generated confidence numbers are not calibrated') "
                "into a measured result."
            ),
            "transport": (
                "All LLM calls via the local `claude` CLI on the project subscription "
                "(no API key); responses cached at responses.jsonl keyed by "
                "sha256(model + NUL + prompt); exact prompts logged to prompts.jsonl "
                "under the same key."
            ),
            "limitations": [
                "Single-pass: each event scored once by the LLM; no self-consistency "
                "averaging, so per-event scores carry sampling noise.",
                "Subset a labels come from auto_label_event, which shares its "
                "process/EID vocabulary with the classifier's features — CIRCULAR for "
                "the classifier (its calibration on subset a is flattered), independent "
                "evidence only for the LLM judge.",
                "Subset c labels come from label_by_technique (see "
                "run_large_independent_eval.py header for its rule-agreement caveats).",
                "Subset b is hand-authored, not captured telemetry — its FP rates are "
                "not deployment FP-rate estimates (see run_hard_benign_eval.py).",
                "Refusals / unparseable-after-retry are recorded as p=None, counted, "
                "and excluded from metric computation (never fabricated); when any "
                "occur, classifier_matched_to_llm_valid gives the strict head-to-head.",
                "Hard-benign is single-class (all benign), so its ECE reduces to mean "
                "predicted score; read it as FP-side miscalibration only.",
                "LLM scores are from one model snapshot on one date; the CLI/model "
                "version is recorded in metadata for reproducibility.",
            ],
        },
        "metrics": metrics,
        "hard_benign_fp": hard_benign_fp,
        "per_event": per_event,
    }

    # ── Summary ────────────────────────────────────────────────────────────
    lines = [
        "LLM-Judge Calibration Experiment (report section 4.5, measured)",
        "=" * 70,
        "",
        f"Model: {args.model} via claude CLI ({results['metadata']['claude_cli_version']})",
        f"Classifier: {results['metadata']['classifier_model']} (k={WINDOW_SIZE})",
        f"Seed: {SEED}  |  bins: {N_BINS} (same as run_calibration_eval.py)"
        + (f"  |  --limit {args.limit} (SMOKE RUN)" if args.limit is not None else ""),
        "",
        "Subsets: a) train_pool  = auto_label labels (circular for classifier,",
        "            independent for LLM judge)",
        "         b) hard_benign = 152 hand-authored benign admin events",
        "         c) eval_holdout = label_by_technique labels, stratified sample",
        "",
        "Head-to-head overview (LLM judge | classifier):",
        f"  {'Subset':<14} {'n':>5} {'null':>5} {'ECE':>15} {'Brier':>15} {'desert%':>15}",
        f"  {'-'*72}",
    ]

    def _pair(block: dict, field: str) -> str:
        llm, clf = block["llm_judge"], block["classifier"]
        if field == "desert":
            l = f"{llm['histogram']['desert_mass_0.1_0.9']*100:5.1f}" if llm else "   --"
            c = f"{clf['histogram']['desert_mass_0.1_0.9']*100:5.1f}" if clf else "   --"
        else:
            l = f"{llm['calibration'][field]:.4f}" if llm else "  --  "
            c = f"{clf['calibration'][field]:.4f}" if clf else "  --  "
        return f"{l} | {c}"

    for name in (*SUBSETS, "overall"):
        m = metrics[name]
        lines.append(
            f"  {name:<14} {m['n']:>5} {m['llm_null_count']:>5}"
            f" {_pair(m, 'ece'):>15} {_pair(m, 'brier'):>15} {_pair(m, 'desert'):>15}"
        )

    for name in (*SUBSETS, "overall"):
        m = metrics[name]
        lines += [
            "",
            f"── {name} (n={m['n']}: {m['n_malicious']} malicious, {m['n_benign']} benign; "
            f"LLM null={m['llm_null_count']}, cached={m['llm_cached_count']}) " + "─" * 10,
        ]
        lines += _format_scorer("LLM judge", m["llm_judge"])
        lines += _format_scorer("Classifier", m["classifier"])
        if "classifier_matched_to_llm_valid" in m:
            lines += _format_scorer(
                "Classifier (matched to LLM-valid)", m["classifier_matched_to_llm_valid"]
            )

    lines += ["", "Hard-benign FP rates (every malicious verdict is a false positive):"]
    for scorer, blocks in hard_benign_fp.items():
        if blocks is None:
            lines.append(f"  {scorer}: no scored events")
            continue
        for block in blocks:
            lines.append(_format_fp_line(f"{scorer} p* >= {block['threshold']:.2f}:", block))

    lines += ["", "Limitations:"]
    lines += [f"  - {item}" for item in results["provenance"]["limitations"]]
    lines += [
        "",
        "Library versions: "
        + ", ".join(f"{k}={v}" for k, v in results["metadata"]["library_versions"].items()),
    ]

    summary = "\n".join(lines)
    print(f"\n{summary}")
    (OUT_DIR / "summary.txt").write_text(summary)
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))
    print(f"\nResults -> {OUT_DIR}/")


if __name__ == "__main__":
    main()
