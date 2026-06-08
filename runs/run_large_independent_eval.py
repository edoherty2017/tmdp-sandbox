"""Large independent evaluation — 15 held-out OTRF ZIPs, 10 MITRE techniques.

Methodological guarantees:
  1. All 15 ZIPs are completely separate from the 8 ZIPs used for training.
  2. Ground-truth labels are assigned by technique-specific rules derived from
     MITRE ATT&CK semantics — NOT by auto_label_event() (which uses the same
     LOLBin lists as Phase 1 features). Labels are written to a JSON file BEFORE
     any model scoring occurs.
  3. No iteration: results are reported as-is. If the model fails on a technique,
     that failure is reported, not fixed and re-evaluated.

Label assignment rules (pre-committed, technique-specific):
  T1003.001  LSASS dump:       EID 10 targeting lsass.exe; OR cmdline ∋ mimikatz/sekurlsa/logonpasswords/MiniDump/comsvcs
  T1003.002  SAM dump:         EID 12/13 on \\SAM registry path; OR cmdline ∋ mimikatz/lsadump/sam
  T1003.003  NTDS.dit dump:    cmdline ∋ ntdsutil; OR EID 1/4688 with ntdsutil.exe
  T1558.003  Kerberoasting:    cmdline ∋ rubeus/asktgt/kerberoast/Invoke-Kerberoast
  T1053.005  Sched task:       EID 4698 (task created) OR EID 1/4688 with schtasks.exe /create
  T1547.001  Registry run key: EID 12/13 on \\Run\\ or \\RunOnce\\ path; OR reg.exe add with Run path
  T1546.003  WMI subscription: cmdline ∋ __EventFilter/__EventConsumer/ActiveScript/CommandLine
  T1087.001  Acct discovery:   EID 1/4688 with (net.exe OR net1.exe) AND (user OR users) in cmdline
  T1069.001  Group discovery:  EID 1/4688 with (net.exe OR net1.exe) AND localgroup in cmdline
  T1059.005  VBScript:         EID 1/4688 with wscript.exe OR cscript.exe; OR .vbs in cmdline
  T1047     WMI execution:    EID 1/4688 with wmic.exe; OR cmdline ∋ IWbemServices/Win32_Process
  T1021.006  WinRM:            cmdline ∋ Enter-PSSession/Invoke-Command/New-PSSession/psremot

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_large_independent_eval.py

Outputs:
    runs/large_independent_eval/ground_truth_labels.json  — labels written FIRST
    runs/large_independent_eval/scores.json               — model scores written AFTER
    runs/large_independent_eval/results.json              — metrics per technique
    runs/large_independent_eval/summary.txt               — human-readable report
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier
from tmdp_sandbox.preprocessing import load_otrf_dataset
from tmdp_sandbox.event_spec import EventSpec

REPO      = Path(__file__).parent.parent
EVAL_DIR  = REPO / "data" / "raw" / "eval_holdout"
MODEL     = REPO / "models" / "ml_classifier_logistic.joblib"
OUT_DIR   = Path(__file__).parent / "large_independent_eval"
OUT_DIR.mkdir(parents=True, exist_ok=True)

P_STAR = 0.40   # T-MDP threshold (same as all other experiments)

# ---------------------------------------------------------------------------
# Dataset manifest — 15 ZIPs, 10 techniques, 5 tactic categories
# ---------------------------------------------------------------------------
DATASETS = [
    # zip_name                                                   technique    tactic
    ("empire_mimikatz_logonpasswords.zip",                      "T1003.001", "Credential Access"),
    ("psh_lsass_memory_dump_comsvcs.zip",                       "T1003.001", "Credential Access"),
    ("empire_mimikatz_sam_access.zip",                          "T1003.002", "Credential Access"),
    ("empire_shell_rubeus_asktgt_createnetonly.zip",            "T1558.003", "Credential Access"),
    ("cmd_dumping_ntds_dit_file_ntdsutil.zip",                  "T1003.003", "Credential Access"),
    ("empire_schtasks_creation_execution_elevated_user.zip",    "T1053.005", "Persistence"),
    ("empire_schtasks_creation_standard_user.zip",              "T1053.005", "Persistence"),
    ("empire_persistence_registry_modification_run_keys_elevated_user.zip", "T1547.001", "Persistence"),
    ("empire_persistence_registry_modification_run_keys_standard_user.zip", "T1547.001", "Persistence"),
    ("empire_wmi_local_event_subscriptions_elevated_user.zip",  "T1546.003", "Persistence"),
    ("empire_shell_net_local_users.zip",                        "T1087.001", "Discovery"),
    ("empire_shell_net_localgroup_administrators.zip",          "T1069.001", "Discovery"),
    ("empire_launcher_vbs.zip",                                 "T1059.005", "Execution"),
    ("empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip",      "T1047",     "Lateral Movement"),
    ("covenant_psremoting_command.zip",                         "T1021.006", "Lateral Movement"),
]

# ---------------------------------------------------------------------------
# Pre-committed label rules — assigned by technique semantics ONLY
# Returns "malicious", "benign", or None (excluded = ambiguous)
# ---------------------------------------------------------------------------

def _lower(*fields: str | None) -> str:
    return " ".join(f.lower() for f in fields if f)


def label_by_technique(event: EventSpec, technique: str) -> str | None:
    cmd  = (event.command_line or "").lower()
    proc = (event.process_name or "").lower()
    eid  = event.event_id

    if technique == "T1003.001":
        # LSASS memory dump: process access to lsass, or dump-specific cmdlines
        if eid == 10 and "lsass" in (event.raw_log or "").lower():
            return "malicious"
        dump_terms = ["sekurlsa", "logonpasswords", "minidump", "comsvcs", "lsass.dmp",
                      "lsass.exe", "lsasrv", "wdigest"]
        if any(t in cmd for t in dump_terms) and proc not in ("svchost.exe", "lsass.exe"):
            return "malicious"
        if eid in (1, 4688) and any(t in cmd for t in ["sekurlsa", "logonpasswords", "comsvcs"]):
            return "malicious"
        if eid in (1, 4688) and proc in ("lsass.exe",):
            return None  # lsass itself starting = ambiguous
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe", "runtimebroker.exe"):
            return "benign"
        return None

    elif technique == "T1003.002":
        # SAM database dump
        sam_terms = ["lsadump::sam", "reg save.*sam", r"\sam", "hklm\\sam",
                     "secretsdump", "pwdump", "fgdump"]
        if any(t in cmd for t in sam_terms):
            return "malicious"
        if eid in (12, 13) and "\\sam" in (event.raw_log or "").lower():
            return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1003.003":
        # NTDS.dit dump via ntdsutil
        if "ntdsutil" in cmd or "ntdsutil" in proc:
            return "malicious"
        if "ntds.dit" in cmd or "ntds\\ntds.dit" in cmd:
            return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1558.003":
        # Kerberoasting via Rubeus or Invoke-Kerberoast
        kerb_terms = ["rubeus", "asktgt", "asktgs", "kerberoast", "invoke-kerberoast",
                      "request_etype", "rc4_hmac", "aes256_cts"]
        if any(t in cmd for t in kerb_terms):
            return "malicious"
        if eid == 4769 and "rc4" in (event.raw_log or "").lower():  # kerberos ticket with RC4
            return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe", "lsass.exe"):
            return "benign"
        return None

    elif technique == "T1053.005":
        # Scheduled task creation
        if eid == 4698:  # Windows Security: scheduled task created
            return "malicious"
        if eid in (1, 4688) and "schtasks" in proc:
            if any(t in cmd for t in ["/create", "-create", "/tr ", "/sc ", "/tn "]):
                return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe", "runtimebroker.exe"):
            return "benign"
        return None

    elif technique == "T1547.001":
        # Registry run key persistence
        run_paths = ["\\software\\microsoft\\windows\\currentversion\\run",
                     "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run",
                     "hkcu\\software\\microsoft\\windows\\currentversion\\run",
                     "hklm\\software\\microsoft\\windows\\currentversion\\run"]
        if eid in (12, 13):
            raw = (event.raw_log or "").lower()
            if any(p in raw for p in run_paths):
                return "malicious"
        if eid in (1, 4688) and "reg.exe" in proc:
            if any(p in cmd for p in ["\\run\\", "\\runonce\\", "currentversion\\run"]):
                return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1546.003":
        # WMI event subscription persistence
        wmi_terms = ["__eventfilter", "__eventconsumer", "__filtertoconsumerbinding",
                     "activescripteventconsumer", "commandlineeventconsumer",
                     "wmi subscription", "mof", "scrcons"]
        raw = (event.raw_log or "").lower()
        if any(t in cmd or t in raw for t in wmi_terms):
            return "malicious"
        if eid in (1, 4688) and "scrcons.exe" in proc:
            return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1087.001":
        # Local account discovery via net user
        if eid in (1, 4688) and proc in ("net.exe", "net1.exe"):
            if any(t in cmd for t in ["user", " /domain"]):
                return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1069.001":
        # Permission group discovery via net localgroup
        if eid in (1, 4688) and proc in ("net.exe", "net1.exe"):
            if "localgroup" in cmd:
                return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1059.005":
        # VBScript execution
        if eid in (1, 4688) and proc in ("wscript.exe", "cscript.exe"):
            return "malicious"
        if ".vbs" in cmd and eid in (1, 4688):
            return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1047":
        # WMI execution
        if eid in (1, 4688) and "wmic" in proc:
            return "malicious"
        wmi_exec_terms = ["win32_process", "iwbemservices", "execmethod", "create",
                          "wmi", "powershell.*wmi", "invoke-wmimeth"]
        if any(t in cmd for t in wmi_exec_terms) and proc not in ("svchost.exe",):
            return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    elif technique == "T1021.006":
        # WinRM / PSRemoting
        ps_terms = ["enter-pssession", "invoke-command", "new-pssession",
                    "psremot", "winrm", "wsmprovhost"]
        if any(t in cmd for t in ps_terms):
            return "malicious"
        if eid in (1, 4688) and "wsmprovhost" in proc:
            return "malicious"
        if eid in (1, 4688) and proc in ("svchost.exe", "explorer.exe"):
            return "benign"
        return None

    return None


# ---------------------------------------------------------------------------
# STEP 1 — Load all events and assign labels (BEFORE any model scoring)
# ---------------------------------------------------------------------------
def load_and_label() -> tuple[list[dict], dict]:
    all_labeled: list[dict] = []
    stats: dict[str, dict] = {}

    for zip_name, technique, tactic in DATASETS:
        path = EVAL_DIR / zip_name
        if not path.exists():
            print(f"  MISSING: {zip_name}")
            continue

        try:
            events = load_otrf_dataset(path, label="benign")  # placeholder; overwritten by label_by_technique
        except Exception as e:
            print(f"  LOAD ERROR {zip_name}: {e}")
            continue
        n_mal = n_ben = n_excl = 0

        for i, event in enumerate(events):
            assigned = label_by_technique(event, technique)
            if assigned is None:
                n_excl += 1
                continue
            if assigned == "malicious":
                n_mal += 1
            else:
                n_ben += 1

            all_labeled.append({
                "source_zip": zip_name,
                "technique":  technique,
                "tactic":     tactic,
                "event_idx":  i,
                "ground_truth": assigned,
                # store event fields so we can reconstruct it later
                "process_name":  event.process_name,
                "command_line":  event.command_line,
                "parent_process": event.parent_process,
                "user_name":     event.user_name,
                "event_id":      event.event_id,
                "raw_log":       (event.raw_log or "")[:300],
            })

        stats[zip_name] = {
            "technique": technique,
            "tactic": tactic,
            "malicious": n_mal,
            "benign": n_ben,
            "excluded": n_excl,
            "total": n_mal + n_ben + n_excl,
        }
        print(f"  {zip_name}: {n_mal} malicious, {n_ben} benign, {n_excl} excluded")

    return all_labeled, stats


# ---------------------------------------------------------------------------
# STEP 2 — Score with model (AFTER labels are written)
# ---------------------------------------------------------------------------
def score_events(labeled: list[dict], classifier: MLCommandClassifier) -> list[dict]:
    scored = []
    for entry in labeled:
        event = EventSpec(
            process_name  = entry["process_name"] or "",
            command_line  = entry["command_line"] or "",
            parent_process= entry["parent_process"] or "",
            user_name     = entry["user_name"] or "",
            event_id      = entry["event_id"],
            label         = entry["ground_truth"],
            raw_log       = entry["raw_log"],
        )
        # Use score_event with empty context (conservative: no window advantage)
        score = classifier.score_event(event, (), 0)
        result = dict(entry)
        result["score"]      = round(score, 6)
        result["prediction"] = "malicious" if score >= P_STAR else "benign"
        result["correct"]    = result["prediction"] == entry["ground_truth"]
        scored.append(result)
    return scored


# ---------------------------------------------------------------------------
# STEP 3 — Compute metrics per technique
# ---------------------------------------------------------------------------
def compute_metrics(scored: list[dict]) -> dict:
    from collections import defaultdict
    by_technique: dict[str, list[dict]] = defaultdict(list)
    for r in scored:
        by_technique[r["technique"]].append(r)

    results = {}
    for technique, rows in sorted(by_technique.items()):
        mal_rows = [r for r in rows if r["ground_truth"] == "malicious"]
        ben_rows = [r for r in rows if r["ground_truth"] == "benign"]

        tp = sum(1 for r in mal_rows if r["prediction"] == "malicious")
        fn = sum(1 for r in mal_rows if r["prediction"] == "benign")
        fp = sum(1 for r in ben_rows if r["prediction"] == "malicious")
        tn = sum(1 for r in ben_rows if r["prediction"] == "benign")

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)

        # Find tactic from first row
        tactic = rows[0]["tactic"]
        results[technique] = {
            "tactic":    tactic,
            "n_malicious": len(mal_rows),
            "n_benign":    len(ben_rows),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall":    round(recall,    4),
            "f1":        round(f1,        4),
        }
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 68)
    print("LARGE INDEPENDENT EVALUATION — 15 ZIPs, 10 MITRE Techniques")
    print("=" * 68)

    # --- STEP 1: label (written before any model scoring) ---
    print("\nSTEP 1: Assigning ground-truth labels (technique semantics only) ...")
    labeled, load_stats = load_and_label()

    n_mal_total = sum(1 for r in labeled if r["ground_truth"] == "malicious")
    n_ben_total = sum(1 for r in labeled if r["ground_truth"] == "benign")
    print(f"\n  Total labeled: {len(labeled)} events ({n_mal_total} malicious, {n_ben_total} benign)")

    # Write labels to disk — this is the committed ground truth
    labels_path = OUT_DIR / "ground_truth_labels.json"
    labels_path.write_text(json.dumps(labeled, indent=2))
    print(f"  Labels written → {labels_path}")
    print("  *** Model scoring has NOT occurred yet ***\n")

    # --- STEP 2: score ---
    print("STEP 2: Loading classifier and scoring events ...")
    if not MODEL.exists():
        print(f"ERROR: model not found at {MODEL}. Run: python runs/train_classifier.py")
        return

    pipeline   = load_classifier(MODEL)
    classifier = MLCommandClassifier(pipeline, window_size=10)
    scored     = score_events(labeled, classifier)

    scores_path = OUT_DIR / "scores.json"
    scores_path.write_text(json.dumps(scored, indent=2))
    print(f"  Scores written → {scores_path}")

    # --- STEP 3: metrics ---
    print("\nSTEP 3: Computing metrics ...")
    metrics = compute_metrics(scored)

    # Overall
    all_mal = [r for r in scored if r["ground_truth"] == "malicious"]
    all_ben = [r for r in scored if r["ground_truth"] == "benign"]
    tp_all = sum(1 for r in all_mal if r["prediction"] == "malicious")
    fn_all = sum(1 for r in all_mal if r["prediction"] == "benign")
    fp_all = sum(1 for r in all_ben if r["prediction"] == "malicious")
    tn_all = sum(1 for r in all_ben if r["prediction"] == "benign")
    prec_all = tp_all / (tp_all + fp_all) if (tp_all + fp_all) > 0 else 0
    rec_all  = tp_all / (tp_all + fn_all) if (tp_all + fn_all) > 0 else 0
    f1_all   = 2 * prec_all * rec_all / (prec_all + rec_all) if (prec_all + rec_all) > 0 else 0

    overall = {
        "n_malicious": len(all_mal),
        "n_benign":    len(all_ben),
        "tp": tp_all, "fp": fp_all, "fn": fn_all, "tn": tn_all,
        "precision": round(prec_all, 4),
        "recall":    round(rec_all,  4),
        "f1":        round(f1_all,   4),
    }

    results = {"per_technique": metrics, "overall": overall, "load_stats": load_stats}
    results_path = OUT_DIR / "results.json"
    results_path.write_text(json.dumps(results, indent=2))

    # --- Print summary ---
    lines = []
    lines.append("=" * 68)
    lines.append("LARGE INDEPENDENT EVALUATION RESULTS")
    lines.append(f"Threshold p* = {P_STAR}  |  No iteration on test set")
    lines.append("=" * 68)
    lines.append(f"\n{'Technique':<14} {'Tactic':<20} {'n_mal':>6} {'n_ben':>6} "
                 f"{'Prec':>6} {'Rec':>6} {'F1':>6} {'FN':>4} {'FP':>4}")
    lines.append("-" * 80)

    for tech, m in sorted(metrics.items()):
        lines.append(
            f"{tech:<14} {m['tactic']:<20} {m['n_malicious']:>6} {m['n_benign']:>6} "
            f"{m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} "
            f"{m['fn']:>4} {m['fp']:>4}"
        )

    lines.append("-" * 80)
    lines.append(
        f"{'OVERALL':<14} {'':<20} {overall['n_malicious']:>6} {overall['n_benign']:>6} "
        f"{overall['precision']:>6.3f} {overall['recall']:>6.3f} {overall['f1']:>6.3f} "
        f"{overall['fn']:>4} {overall['fp']:>4}"
    )
    lines.append("")
    lines.append(f"Total events evaluated: {len(scored)}")
    lines.append(f"  Malicious: {len(all_mal)}, Benign: {len(all_ben)}")
    lines.append(f"  TP={tp_all}  FP={fp_all}  FN={fn_all}  TN={tn_all}")
    lines.append("")
    lines.append("Comparison to prior evaluations:")
    lines.append(f"  CV F1 (in-distribution, n=12,409):       0.997")
    lines.append(f"  Cross-technique F1 (n=1,496, 2 ZIPs):    0.921")
    lines.append(f"  Independent eval (n=30, 5 techniques):   1.000  [CONTAMINATED]")
    lines.append(f"  This eval (n={len(scored)}, 10 techniques, 15 ZIPs): {f1_all:.3f}")

    summary = "\n".join(lines)
    print("\n" + summary)
    summary_path = OUT_DIR / "summary.txt"
    summary_path.write_text(summary)
    print(f"\nFull results → {OUT_DIR}/")


if __name__ == "__main__":
    main()
