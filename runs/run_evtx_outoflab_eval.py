"""Out-of-lab evaluation — EVTX-ATTACK-SAMPLES (sbousseaden), a DIFFERENT source
than the OTRF/Mordor lab the classifier was trained on.

Motivation (review finding, report §6.7 / §7.5): every number in the report comes
from the OTRF theshire lab — same hosts, operator, and recording pipeline for both
train and "held-out" data, so "generalization" was never actually tested out of
distribution. EVTX-ATTACK-SAMPLES is an independently collected corpus of Windows
event-log captures (Sysmon + Security channels) organized by MITRE ATT&CK, authored
by a different researcher on different machines. Applying the OTRF-trained model here
is the first genuine out-of-distribution test.

Protocol (mirrors runs/run_large_independent_eval.py, the corrected labels-first
harness):
  STEP 0  Convert each .evtx to flattened JSON records (cached, deterministic).
  STEP 1  Label every event with the FROZEN auto_label_event rule, committed to
          ground_truth_labels.json BEFORE any model scoring. Ambiguous -> excluded.
  STEP 2  Score once with the OTRF-trained model, using the real k=10 context window
          within each capture. No iteration, no re-scoring.
  STEP 3  Report P/R/F1 + trivial baselines (21-/3-process whitelist) + the
          label-free model-vs-whitelist agreement rate + Wilson / cluster-bootstrap CIs.

HONEST CAVEATS (disclosed, not worked around):
  * The frozen labeler is auto_label_event, which shares its process/EID vocabulary
    with the classifier's features (same circularity the report already discloses for
    the OTRF eval). So the P/R/F1 here are NOT independent of the labeling rule. The
    decision-relevant, LABEL-FREE signal is `whitelist_agreement`: if the OTRF-trained
    model still coincides with a 21-process whitelist on this different corpus, it
    generalized nothing beyond process names; if agreement drops, it learned something
    transferable. Read that number first.
  * Technique is parsed from each filename's tXXXX tag; tactic from the top folder.
    Files with no tag are grouped as "unknown" but still scored.
  * These captures are attack-focused; benign events are incidental background, so the
    class balance is not a deployment base rate.

Outputs (runs/evtx_outoflab_eval/): ground_truth_labels.json, scores.json,
results.json, summary.txt.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier  # noqa: E402
from tmdp_sandbox.event_spec import EventSpec  # noqa: E402
from tmdp_sandbox.preprocessing import auto_label_event, load_otrf_dataset  # noqa: E402

# Reuse the exact baseline/CI machinery from the OTRF eval so the two are comparable.
from run_large_independent_eval import (  # noqa: E402
    _BASELINE_PROCESSES,
    _THREE_PROCESS_WHITELIST,
    _confusion,
    _model_pred,
    _whitelist_21_pred,
    cluster_bootstrap_f1_ci,
    wilson_ci,
)

DATA_DIR  = REPO / "data" / "raw" / "evtx_attack_samples"
CACHE_DIR = DATA_DIR / "_converted"
OUT_DIR   = REPO / "runs" / "evtx_outoflab_eval"
MODEL     = REPO / "models" / "ml_classifier_logistic.joblib"
P_STAR    = 0.40

_TECH_RE = re.compile(r"[_\-]?(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# STEP 0 — Convert .evtx -> flattened JSONL (Sysmon/Security field names at top
# level, the shape load_otrf_dataset already parses). Cached and deterministic.
# ---------------------------------------------------------------------------
def _eventid(system: dict) -> int | None:
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text", eid.get("Qualifiers"))
    try:
        return int(eid)
    except (TypeError, ValueError):
        return None


def convert_evtx(evtx_path: Path, cache_path: Path) -> int:
    """Write one flattened JSON object per record to cache_path. Returns count."""
    from evtx import PyEvtxParser

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with cache_path.open("w", encoding="utf-8") as out:
        parser = PyEvtxParser(str(evtx_path))
        for rec in parser.records_json():
            try:
                ev = json.loads(rec["data"]).get("Event", {})
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
            system = ev.get("System", {}) or {}
            data = ev.get("EventData", {}) or {}
            if not isinstance(data, dict):
                data = {}
            flat = dict(data)
            flat["EventID"] = _eventid(system)
            chan = system.get("Channel")
            if chan:
                flat["Channel"] = chan
            out.write(json.dumps(flat) + "\n")
            n += 1
    return n


def technique_of(path: Path) -> str:
    m = _TECH_RE.search(path.name)
    return m.group(1).upper() if m else "UNKNOWN"


def tactic_of(path: Path) -> str:
    rel = path.relative_to(DATA_DIR)
    return rel.parts[0] if len(rel.parts) > 1 else "Root"


# ---------------------------------------------------------------------------
# STEP 1 — Load + FROZEN labels (written before scoring)
# ---------------------------------------------------------------------------
def load_and_label():
    labeled: list[dict] = []
    stats: dict[str, dict] = {}
    sequences: dict[str, tuple[EventSpec, ...]] = {}

    evtx_files = sorted(
        p for p in DATA_DIR.rglob("*.evtx") if CACHE_DIR not in p.parents
    )
    print(f"Found {len(evtx_files)} .evtx files")

    for evtx_path in evtx_files:
        key = str(evtx_path.relative_to(DATA_DIR))
        cache_path = CACHE_DIR / (key + ".jsonl")
        try:
            if not cache_path.exists():
                convert_evtx(evtx_path, cache_path)
            events = load_otrf_dataset(cache_path, label="benign")
        except Exception as e:  # noqa: BLE001
            print(f"  SKIP {key}: {type(e).__name__}: {e}")
            continue

        sequences[key] = tuple(events)
        technique = technique_of(evtx_path)
        tactic = tactic_of(evtx_path)
        n_mal = n_ben = n_excl = 0

        for i, event in enumerate(events):
            assigned = auto_label_event(event)  # FROZEN, pre-committed labeler
            if assigned is None:
                n_excl += 1
                continue
            if assigned == "malicious":
                n_mal += 1
            else:
                n_ben += 1
            labeled.append({
                "source_file": key,
                "source_zip": key,  # alias: cluster_bootstrap_f1_ci clusters on this key
                "technique": technique,
                "tactic": tactic,
                "event_idx": i,
                "ground_truth": assigned,
                "process_name": event.process_name,
                "command_line": event.command_line,
                "parent_process": event.parent_process,
                "user_name": event.user_name,
                "event_id": event.event_id,
                "raw_log": (event.raw_log or "")[:300],
            })
        stats[key] = {
            "technique": technique, "tactic": tactic,
            "malicious": n_mal, "benign": n_ben, "excluded": n_excl,
            "total": len(events),
        }
    return labeled, stats, sequences


# ---------------------------------------------------------------------------
# STEP 2 — Score (after labels committed)
# ---------------------------------------------------------------------------
def score_events(labeled, sequences, clf: MLCommandClassifier):
    scored = []
    for entry in labeled:
        seq = sequences[entry["source_file"]]
        idx = entry["event_idx"]
        score = clf.score_event(seq[idx], seq, idx)
        r = dict(entry)
        r["score"] = round(score, 6)
        r["prediction"] = "malicious" if score >= P_STAR else "benign"
        r["correct"] = r["prediction"] == entry["ground_truth"]
        scored.append(r)
    return scored


# ---------------------------------------------------------------------------
# STEP 3 — Metrics
# ---------------------------------------------------------------------------
def _prf(conf: dict) -> dict:
    tp, fp, fn = conf["tp"], conf["fp"], conf["fn"]
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {**conf, "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)}


def whitelist_agreement(scored) -> dict:
    n_agree = sum(1 for r in scored if _model_pred(r) == _whitelist_21_pred(r))
    return {"n_agree": n_agree, "n_events": len(scored),
            "agreement_rate": round(n_agree / len(scored), 4) if scored else 0.0}


def compute(scored) -> dict:
    def w3(r):
        return (r["process_name"] or "").lower() not in _THREE_PROCESS_WHITELIST

    model_conf = _confusion(scored, _model_pred)
    tp = model_conf["tp"] + model_conf["fn"]
    tn = model_conf["tn"] + model_conf["fp"]
    return {
        "n_events": len(scored),
        "n_malicious": tp,
        "n_benign": tn,
        "model": _prf(model_conf),
        "baselines": {
            "always_malicious": _prf(_confusion(scored, lambda r: True)),
            "whitelist_21_process": _prf(_confusion(scored, _whitelist_21_pred)),
            "whitelist_3_process": _prf(_confusion(scored, w3)),
        },
        "whitelist_agreement": whitelist_agreement(scored),
        "recall_wilson_ci": wilson_ci(model_conf["tp"], model_conf["tp"] + model_conf["fn"]),
        "precision_wilson_ci": wilson_ci(model_conf["tp"], model_conf["tp"] + model_conf["fp"]),
        "f1_cluster_bootstrap_ci": cluster_bootstrap_f1_ci(scored),
    }


def per_tactic(scored) -> dict:
    from collections import defaultdict
    groups: dict[str, list] = defaultdict(list)
    for r in scored:
        groups[r["tactic"]].append(r)
    out = {}
    for tac, rows in sorted(groups.items()):
        conf = _confusion(rows, _model_pred)
        agree = sum(1 for r in rows if _model_pred(r) == _whitelist_21_pred(r))
        out[tac] = {**_prf(conf), "n": len(rows),
                    "whitelist_agreement": round(agree / len(rows), 4) if rows else 0.0}
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not MODEL.exists():
        print(f"MISSING model: {MODEL} — run runs/train_classifier.py first")
        sys.exit(1)

    print("STEP 1 — converting + labeling (frozen auto_label_event) ...")
    labeled, stats, sequences = load_and_label()
    n_mal = sum(1 for r in labeled if r["ground_truth"] == "malicious")
    n_ben = len(labeled) - n_mal
    total_seen = sum(s["total"] for s in stats.values())
    print(f"  {len(labeled)} labeled ({n_mal} malicious, {n_ben} benign) "
          f"from {total_seen} events across {len(stats)} files")

    (OUT_DIR / "ground_truth_labels.json").write_text(json.dumps(
        {"protocol": "labels-first; auto_label_event frozen before scoring",
         "labeler": "auto_label_event",
         "n_labeled": len(labeled), "n_malicious": n_mal, "n_benign": n_ben,
         "per_file": stats,
         "labels": [{"source_file": r["source_file"], "event_idx": r["event_idx"],
                     "ground_truth": r["ground_truth"]} for r in labeled]},
        indent=1))
    print("  >> ground_truth_labels.json written. Model scoring has NOT occurred yet.")

    print("STEP 2 — scoring with OTRF-trained model (real k=10 context) ...")
    clf = MLCommandClassifier(load_classifier(MODEL), window_size=10)
    scored = score_events(labeled, sequences, clf)
    (OUT_DIR / "scores.json").write_text(json.dumps(scored, indent=1))

    print("STEP 3 — metrics ...")
    m = compute(scored)
    m["per_tactic"] = per_tactic(scored)
    m["library_versions"] = _versions()
    (OUT_DIR / "results.json").write_text(json.dumps(m, indent=1))
    _write_summary(m, stats, total_seen)
    print(f"\nDone. Artifacts in {OUT_DIR}/")


def _versions() -> dict:
    import importlib.metadata as md
    out = {"python": sys.version.split()[0]}
    for pkg in ("scikit-learn", "numpy", "joblib", "evtx"):
        try:
            out[pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            pass
    return out


def _write_summary(m: dict, stats: dict, total_seen: int) -> None:
    L = []
    L.append("Out-of-Lab Evaluation — EVTX-ATTACK-SAMPLES (sbousseaden)")
    L.append("=" * 64)
    L.append("The OTRF-trained classifier applied to an independently collected")
    L.append("Windows event-log corpus (different author, machines, pipeline).")
    L.append("")
    L.append(f"Corpus funnel: {total_seen} events in {len(stats)} .evtx files "
             f"-> {m['n_events']} labeled ({m['n_malicious']} malicious, "
             f"{m['n_benign']} benign), {total_seen - m['n_events']} excluded.")
    L.append("")
    mo = m["model"]
    L.append(f"MODEL (OTRF-trained, p*={P_STAR}):  "
             f"P={mo['precision']}  R={mo['recall']}  F1={mo['f1']}  "
             f"(TP={mo['tp']} FP={mo['fp']} FN={mo['fn']} TN={mo['tn']})")
    L.append(f"  Recall Wilson 95% CI:    {m['recall_wilson_ci']}")
    L.append(f"  Precision Wilson 95% CI: {m['precision_wilson_ci']}")
    L.append(f"  F1 cluster-bootstrap CI (files resampled): {m['f1_cluster_bootstrap_ci']}")
    L.append("")
    L.append("Trivial baselines (same ground truth):")
    for name, b in m["baselines"].items():
        L.append(f"  {name:22s} P={b['precision']:.3f} R={b['recall']:.3f} "
                 f"F1={b['f1']:.3f} (FP={b['fp']}, FN={b['fn']})")
    L.append("")
    wa = m["whitelist_agreement"]
    L.append("*** LABEL-FREE HEADLINE — does the model still equal a whitelist "
             "on out-of-lab data? ***")
    L.append(f"  Model vs 21-process whitelist agreement: "
             f"{wa['n_agree']}/{wa['n_events']} = {wa['agreement_rate']*100:.1f}%")
    L.append("  (OTRF held-out was 100.0%. Lower here = genuine transferable signal; "
             "still ~100% = learned nothing beyond process names.)")
    L.append("")
    L.append("Per-tactic (model):")
    L.append(f"  {'tactic':28s} {'n':>5} {'P':>6} {'R':>6} {'F1':>6} {'wl_agree':>9}")
    for tac, r in m["per_tactic"].items():
        L.append(f"  {tac[:28]:28s} {r['n']:5d} {r['precision']:6.3f} "
                 f"{r['recall']:6.3f} {r['f1']:6.3f} {r['whitelist_agreement']*100:8.1f}%")
    L.append("")
    L.append("CAVEAT: labels come from auto_label_event, which shares vocabulary with "
             "the model's features (see header). P/R/F1 are therefore not independent of "
             "the labeler; the whitelist-agreement rate above is the label-free signal.")
    L.append(f"\nLibrary versions: {m['library_versions']}")
    (OUT_DIR / "summary.txt").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
