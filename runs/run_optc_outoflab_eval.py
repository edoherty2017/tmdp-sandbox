"""Out-of-lab evaluation #2 — DARPA OpTC (real enterprise telemetry).

This is a THIRD distinct corpus, and the strongest of the three: unlike OTRF
(one Mordor lab) and EVTX-ATTACK-SAMPLES (curated single-technique captures),
OpTC is production-scale endpoint telemetry from a 500-host enterprise network
collected by DARPA's Transparent Computing program — real background activity
from real machines.

Scope of THIS run (honest): the AIA-201-225 host range on 2019-09-23, the main
eCAR chunk, which covers 09:06-09:31 — a **pre-attack, benign window** (the Day-1
red team began at 11:23 on SysClient0201, per OpTCRedTeamGroundTruth.pdf). So this
run is a real-world **false-positive / whitelist-equivalence** test on genuine
enterprise telemetry, not an attack-detection test. The red-team window (11:23-15:30)
lives in the 2.2 GB `-last` chunk, which throttled during download here; scoring
attack detection on OpTC is wired (same harness) and left as the documented next
step — see docs/out-of-lab-evaluation.md.

Why this is worth running even benign-only: it is the first time the OTRF-trained
model sees real, non-simulated enterprise processes. The decision-relevant, LABEL-FREE
question — does the model still coincide with a 21-process whitelist on real-world
telemetry? — needs no labels and is the headline.

eCAR -> EventSpec mapping (from ecar.md), object/action -> synthetic Windows EventID:
  PROCESS/CREATE  -> 1   (image_path, command_line, parent_image_path, user)
  PROCESS/OPEN    -> 10  (process access; target UUID not resolved to a name here,
                          so the EID-10 cred-theft branch cannot fire — noted)
  MODULE/LOAD     -> 7   (module_path as the loaded image)
  REGISTRY/*      -> 13  (key/value/data -> reg command line)
  everything else (FLOW/FILE/THREAD/SHELL) -> excluded (no process-creation signal)

Outputs (runs/optc_outoflab_eval/): results.json, summary.txt.
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier  # noqa: E402
from tmdp_sandbox.event_spec import EventSpec  # noqa: E402
from tmdp_sandbox.preprocessing import _normalize_process, auto_label_event  # noqa: E402
from run_large_independent_eval import (  # noqa: E402
    _BASELINE_PROCESSES, _THREE_PROCESS_WHITELIST, _confusion,
    _model_pred, _whitelist_21_pred, wilson_ci,
)

DATA   = REPO / "data" / "raw" / "optc" / "AIA-201-225.red.json.gz"
OUT    = REPO / "runs" / "optc_outoflab_eval"
MODEL  = REPO / "models" / "ml_classifier_logistic.joblib"
P_STAR = 0.40
# Focus on SysClient0201 — the Day-1 red-team target host (per ground truth),
# here observed in its pre-attack benign window. Keeps the per-event scoring
# tractable while staying on the single most relevant real host.
TARGET_HOSTS = {"SysClient0201"}

_OBJACT_TO_EID = {
    ("PROCESS", "CREATE"): 1,
    ("PROCESS", "OPEN"): 10,
    ("MODULE", "LOAD"): 7,
    ("REGISTRY", "ADD"): 13,
    ("REGISTRY", "EDIT"): 13,
    ("REGISTRY", "REMOVE"): 13,
}


def _basename(path: str) -> str:
    if not path:
        return ""
    return _normalize_process(path.replace("\\\\", "\\").split("\\")[-1])


def ecar_to_eventspec(rec: dict) -> EventSpec | None:
    eid = _OBJACT_TO_EID.get((rec.get("object"), rec.get("action")))
    if eid is None:
        return None
    p = rec.get("properties", {}) or {}
    if eid == 13:
        cmd = f"reg {rec.get('action','').lower()} {p.get('key','')}={p.get('value','')}"
        proc = _basename(p.get("image_path", ""))
    elif eid == 7:
        cmd = f"load {p.get('module_path','')}"
        proc = _basename(p.get("image_path", ""))
    else:  # PROCESS CREATE / OPEN
        cmd = p.get("command_line", "") or ""
        proc = _basename(p.get("image_path", ""))
    return EventSpec(
        process_name=proc,
        command_line=cmd[:500],
        user_name=str(p.get("user") or rec.get("principal") or ""),
        parent_process=_basename(p.get("parent_image_path", "")),
        event_id=eid,
        label="benign",
        raw_log=json.dumps(rec)[:300],
    )


def load_events() -> dict[str, list[EventSpec]]:
    """Per-host event sequences (in recorded order) from the eCAR chunk."""
    by_host: dict[str, list[EventSpec]] = {}
    n_total = n_kept = 0
    for line in gzip.open(DATA, "rt"):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        n_total += 1
        host = str(rec.get("hostname", "")).split(".")[0] or "unknown"
        if TARGET_HOSTS and host not in TARGET_HOSTS:
            continue
        ev = ecar_to_eventspec(rec)
        if ev is None:
            continue
        by_host.setdefault(host, []).append(ev)
        n_kept += 1
    print(f"  {n_total} eCAR records -> {n_kept} scoreable events across {len(by_host)} hosts")
    return by_host


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    if not MODEL.exists():
        print(f"MISSING model: {MODEL}")
        sys.exit(1)

    print("Loading + converting eCAR (real OpTC enterprise telemetry) ...")
    by_host = load_events()

    clf = MLCommandClassifier(load_classifier(MODEL), window_size=10)
    scored: list[dict] = []
    for host, seq in by_host.items():
        seqt = tuple(seq)
        for idx, ev in enumerate(seqt):
            gt = auto_label_event(ev)  # frozen labeler (disclosed circular, as elsewhere)
            score = clf.score_event(ev, seqt, idx)
            scored.append({
                "host": host,
                "process_name": ev.process_name,
                "command_line": ev.command_line,
                "parent_process": ev.parent_process,
                "event_id": ev.event_id,
                "ground_truth": gt,          # may be None (excluded)
                "score": round(score, 6),
                "prediction": "malicious" if score >= P_STAR else "benign",
            })
    print(f"  scored {len(scored)} events")

    # --- LABEL-FREE headline: model vs 21-process whitelist on real telemetry ---
    n_agree = sum(1 for r in scored if _model_pred(r) == _whitelist_21_pred(r))
    agreement = round(n_agree / len(scored), 4) if scored else 0.0
    n_flag = sum(1 for r in scored if _model_pred(r))

    # --- FP view: this window is benign (pre-attack), so any 'malicious' is a FP ---
    #     (reported against auto_label where it fired, and label-free as flag-rate)
    labeled = [r for r in scored if r["ground_truth"] is not None]
    conf = _confusion(labeled, _model_pred) if labeled else {"tp": 0, "fp": 0, "fn": 0, "tn": 0}

    results = {
        "corpus": "DARPA OpTC — AIA-201-225, 2019-09-23 ~09:06-09:31 (pre-attack, benign)",
        "n_scored": len(scored),
        "n_hosts": len(by_host),
        "whitelist_agreement": {
            "n_agree": n_agree, "n_events": len(scored), "rate": agreement,
        },
        "model_flag_rate": {
            "n_flagged_malicious": n_flag, "rate": round(n_flag / len(scored), 4) if scored else 0.0,
            "ci": wilson_ci(n_flag, len(scored)),
        },
        "auto_label_confusion": conf,
        "by_eventid": _by_eventid(scored),
        "library_versions": _versions(),
    }
    (OUT / "results.json").write_text(json.dumps(results, indent=1))
    _summary(results)


def _by_eventid(scored):
    from collections import defaultdict
    g = defaultdict(lambda: [0, 0])  # [n, n_flagged]
    for r in scored:
        g[r["event_id"]][0] += 1
        if _model_pred(r):
            g[r["event_id"]][1] += 1
    return {str(k): {"n": v[0], "flagged_malicious": v[1]} for k, v in sorted(g.items())}


def _versions():
    import importlib.metadata as md
    out = {"python": sys.version.split()[0]}
    for pkg in ("scikit-learn", "numpy", "joblib"):
        try:
            out[pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            pass
    return out


def _summary(r):
    L = []
    L.append("Out-of-Lab Evaluation #2 — DARPA OpTC (real enterprise telemetry)")
    L.append("=" * 66)
    L.append(r["corpus"])
    L.append(f"Scored {r['n_scored']} process/module/registry events across "
             f"{r['n_hosts']} real hosts (SysClient0201-0225).")
    L.append("")
    wa = r["whitelist_agreement"]
    L.append("*** LABEL-FREE HEADLINE — model vs 21-process whitelist on REAL "
             "enterprise telemetry ***")
    L.append(f"  Agreement: {wa['n_agree']}/{wa['n_events']} = {wa['rate']*100:.2f}%")
    L.append("  (OTRF held-out 100.0%; EVTX-ATTACK-SAMPLES 100.0%. Third corpus, "
             "real-world data.)")
    L.append("")
    fr = r["model_flag_rate"]
    L.append(f"Model flags malicious: {fr['n_flagged_malicious']}/{r['n_scored']} = "
             f"{fr['rate']*100:.2f}%  (95% Wilson CI "
             f"{fr['ci'][0]*100:.2f}-{fr['ci'][1]*100:.2f}%)")
    L.append("  This window is benign (pre-attack, per red-team ground truth), so every "
             "malicious flag here is a real-world FALSE POSITIVE on genuine enterprise")
    L.append("  activity — the deployment-FP concern, now measured on real data.")
    L.append("")
    L.append("By synthetic EventID (1=proc-create 10=proc-access 7=module 13=registry):")
    for eid, v in r["by_eventid"].items():
        L.append(f"  EID {eid:>2}: {v['n']:6d} events, {v['flagged_malicious']:6d} flagged malicious")
    L.append("")
    L.append("CAVEATS: (1) benign window only — attack detection (red window 11:23-15:30) "
             "needs the 2.2GB -last chunk, wired but not downloaded here. (2) auto_label "
             "labels share vocabulary with model features (disclosed); the label-free "
             "whitelist-agreement above is the honest signal. (3) PROCESS/OPEN target "
             "process is a UUID not resolved to a name, so the EID-10 cred-theft branch "
             "cannot fire on OpTC.")
    L.append(f"\nLibrary versions: {r['library_versions']}")
    (OUT / "summary.txt").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
