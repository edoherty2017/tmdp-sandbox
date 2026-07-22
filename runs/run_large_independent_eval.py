"""Large independent evaluation — 15 held-out OTRF ZIPs, 12 MITRE techniques.

Methodological guarantees (and their limits):
  1. All 15 ZIPs are completely separate from the 8 ZIPs used for training.
  2. Ground-truth labels are assigned by technique-specific rules and written
     to a JSON file BEFORE any model scoring occurs. This labels-first protocol
     defends ONLY against post-hoc label edits and test-set iteration — it does
     NOT make the labels independent of the Phase 1 feature lists.
     label_by_technique shares process/EID vocabulary with those lists: every
     technique-specific benign clause is a baseline-whitelist membership test
     (the agent-poll guard additionally labels vboxservice.exe/msmpeng.exe
     polls benign), and several
     malicious rules key on _SUSPICIOUS_PROCESSES members (net.exe, wmic.exe,
     wscript.exe, schtasks.exe) or on EID 4698, which the classifier
     hard-scores 0.99. Precision on this corpus therefore measures rule
     agreement, not deployment false-positive behavior.
  3. No iteration: results are reported as-is. If the model fails on a technique,
     that failure is reported, not fixed and re-evaluated.

Label assignment rules (pre-committed, technique-specific):
  Agent polls (all techniques): EID 10 handle opens by hypervisor/AV agents
     (vboxservice.exe, msmpeng.exe) WITHOUT PROCESS_VM_READ (0x0010) are routine
     housekeeping — labeled benign, NOT excluded, so model FPs on them count.
  T1003.001  LSASS dump:       EID 10 targeting lsass.exe with PROCESS_VM_READ access; OR cmdline ∋ mimikatz/sekurlsa/logonpasswords/MiniDump/comsvcs
  T1003.002  SAM dump:         EID 12/13 on \\SAM registry path; OR cmdline ∋ mimikatz/lsadump/sam
  T1003.003  NTDS.dit dump:    cmdline ∋ ntdsutil; OR EID 1/4688 with ntdsutil.exe (EID 10 handle polls excluded)
  T1558.003  Kerberoasting:    cmdline ∋ rubeus/asktgt/kerberoast/Invoke-Kerberoast
  T1053.005  Sched task:       EID 4698 (task created) OR EID 1/4688 with schtasks.exe /create
  T1547.001  Registry run key: EID 12/13 on \\Run\\ or \\RunOnce\\ path; OR reg.exe add with Run path
  T1546.003  WMI subscription: cmdline ∋ __EventFilter/__EventConsumer/ActiveScript/CommandLine
  T1087.001  Acct discovery:   EID 1/4688 with (net.exe OR net1.exe) AND (user OR users) in cmdline
  T1069.001  Group discovery:  EID 1/4688 with (net.exe OR net1.exe) AND localgroup in cmdline
  T1059.005  VBScript:         EID 1/4688 with wscript.exe OR cscript.exe; OR .vbs in cmdline
  T1047     WMI execution:    EID 1/4688 with wmic.exe; OR cmdline ∋ Win32_Process/IWbemServices/ExecMethod/Invoke-WmiMethod (generic EID 4656/4658/4663 audit records excluded)
  T1021.006  WinRM:            cmdline ∋ Enter-PSSession/Invoke-Command/New-PSSession/psremot

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_large_independent_eval.py

Outputs:
    runs/large_independent_eval/ground_truth_labels.json  — labels written FIRST
    runs/large_independent_eval/scores.json               — model scores written AFTER
    runs/large_independent_eval/results.json              — metrics, baselines, CIs, versions
    runs/large_independent_eval/summary.txt               — human-readable report
"""

from __future__ import annotations

import json
import math
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier
from tmdp_sandbox.context_window import _BASELINE_PROCESSES
from tmdp_sandbox.preprocessing import load_otrf_dataset
from tmdp_sandbox.event_spec import EventSpec

REPO      = Path(__file__).parent.parent
EVAL_DIR  = REPO / "data" / "raw" / "eval_holdout"
MODEL     = REPO / "models" / "ml_classifier_logistic.joblib"
OUT_DIR   = Path(__file__).parent / "large_independent_eval"
OUT_DIR.mkdir(parents=True, exist_ok=True)

P_STAR = 0.40   # T-MDP threshold (same as all other experiments)

# ---------------------------------------------------------------------------
# Dataset manifest — 15 ZIPs, 12 techniques, 5 tactic categories
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


# Hypervisor / endpoint-agent processes: their routine EID-10 handle polls
# (query-only masks, no PROCESS_VM_READ) are housekeeping, not attack activity.
_AGENT_PROCESSES = frozenset({"vboxservice.exe", "msmpeng.exe"})
# PROCESS_VM_READ (0x0010) — the access right required to read another
# process's memory; an lsass handle without it cannot dump credentials.
_PROCESS_VM_READ = 0x0010
# Matches "flags=0x1410" (loader-synthesized EID-10 cmdline) or the
# GrantedAccess field in the raw JSON line (hex or decimal).
_ACCESS_MASK_RE = re.compile(r"(?:flags=|grantedaccess\W{0,4})(0x[0-9a-f]+|\d+)")


def _granted_access(event: EventSpec) -> int | None:
    """Parse the Sysmon EID-10 GrantedAccess mask from event text, if present."""
    m = _ACCESS_MASK_RE.search(_lower(event.command_line, event.raw_log))
    if not m:
        return None
    token = m.group(1)
    return int(token, 16) if token.startswith("0x") else int(token)


def label_by_technique(event: EventSpec, technique: str) -> str | None:
    cmd  = (event.command_line or "").lower()
    proc = (event.process_name or "").lower()
    eid  = event.event_id

    # Agent housekeeping (all techniques): EID-10 handle polls by hypervisor/AV
    # agents without PROCESS_VM_READ cannot read process memory — routine
    # monitoring, labeled benign (NOT excluded) so model FPs on them count.
    if eid == 10 and proc in _AGENT_PROCESSES:
        access = _granted_access(event)
        if access is not None and not (access & _PROCESS_VM_READ):
            return "benign"
        return None  # dump-capable or unparseable mask from an agent = ambiguous

    if technique == "T1003.001":
        # LSASS memory dump: dump-capable access to lsass, or dump-specific cmdlines
        if eid == 10 and ("lsass" in cmd or "lsass" in (event.raw_log or "").lower()):
            # Only PROCESS_VM_READ-capable handles can read lsass memory;
            # query-only masks (e.g. 0x1400) are monitoring polls, not dumps.
            # (Agent-process polls already returned benign above.)
            access = _granted_access(event)
            if access is not None and (access & _PROCESS_VM_READ):
                return "malicious"
            return None
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
        if eid == 10:
            # Handle polls against a running ntdsutil.exe are monitoring, not
            # dump evidence — the attack signal is ntdsutil execution below.
            return None
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
        if eid in (4656, 4658, 4663):
            # Generic object-access audit records are ubiquitous benign
            # background (the T1003.003 analysis characterizes the same event
            # species as routine) — excluded, even when WMI paths appear in
            # the audit message text.
            return None
        if eid in (1, 4688) and "wmic" in proc:
            return "malicious"
        # Specific WMI-execution tokens only — bare 'wmi'/'create' substrings
        # match routine WmiPrvSE provider-host boilerplate, not attacks.
        wmi_exec_terms = ["win32_process", "iwbemservices", "execmethod",
                          "invoke-wmimeth"]
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
def load_and_label() -> tuple[list[dict], dict, dict[str, tuple[EventSpec, ...]]]:
    all_labeled: list[dict] = []
    stats: dict[str, dict] = {}
    sequences: dict[str, tuple[EventSpec, ...]] = {}

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
        sequences[zip_name] = tuple(events)  # full recorded order, for context windows
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

    return all_labeled, stats, sequences


# ---------------------------------------------------------------------------
# STEP 2 — Score with model (AFTER labels are written)
# ---------------------------------------------------------------------------
def score_events(
    labeled: list[dict],
    sequences: dict[str, tuple[EventSpec, ...]],
    classifier: MLCommandClassifier,
) -> list[dict]:
    scored = []
    for entry in labeled:
        seq = sequences[entry["source_zip"]]
        idx = entry["event_idx"]
        # Score with the REAL preceding context window: the k=10 events before
        # this one in the ZIP's recorded order — the same context semantics as
        # extract_features_for_sequence() uses at training time.
        score = classifier.score_event(seq[idx], seq, idx)
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
# STEP 4 — Trivial baselines, uncertainty, reproducibility metadata
# ---------------------------------------------------------------------------

# The only processes any technique-specific benign clause accepts (the
# agent-poll guard additionally labels vboxservice.exe/msmpeng.exe benign).
_THREE_PROCESS_WHITELIST = ("svchost.exe", "explorer.exe", "runtimebroker.exe")


def _model_pred(r: dict) -> bool:
    return r["prediction"] == "malicious"


def _prf(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1":        round(f1,        4),
    }


def _confusion(rows: list[dict], predict_malicious) -> dict:
    """Confusion counts + P/R/F1 for an arbitrary row → bool predictor."""
    tp = fp = fn = tn = 0
    for r in rows:
        if r["ground_truth"] == "malicious":
            if predict_malicious(r):
                tp += 1
            else:
                fn += 1
        else:
            if predict_malicious(r):
                fp += 1
            else:
                tn += 1
    return _prf(tp, fp, fn, tn)


def _whitelist_21_pred(r: dict) -> bool:
    """The one-line rule the model must beat: malicious iff the process is
    not in the 21-entry Phase 1 baseline whitelist (_BASELINE_PROCESSES)."""
    return (r["process_name"] or "").lower() not in _BASELINE_PROCESSES


def compute_baselines(scored: list[dict]) -> dict:
    """Trivial baselines evaluated against the same ground truth as the model.

    whitelist_3_process whitelists only the three processes the label rules
    ever call benign; everything else is predicted malicious.
    """
    def whitelist_3(r: dict) -> bool:
        return (r["process_name"] or "").lower() not in _THREE_PROCESS_WHITELIST

    return {
        "always_malicious":     _confusion(scored, lambda r: True),
        "always_benign":        _confusion(scored, lambda r: False),
        "whitelist_21_process": _confusion(scored, _whitelist_21_pred),
        "whitelist_3_process":  _confusion(scored, whitelist_3),
    }


def whitelist_agreement(scored: list[dict]) -> dict:
    """How often the model's prediction equals the 21-process whitelist rule."""
    n_agree = sum(1 for r in scored if _model_pred(r) == _whitelist_21_pred(r))
    return {
        "n_agree":  n_agree,
        "n_events": len(scored),
        "agreement_rate": round(n_agree / len(scored), 4) if scored else 0.0,
    }


def wilson_ci(successes: int, n: int, z: float = 1.96) -> list[float]:
    """Wilson score interval for a binomial proportion (95% at z=1.96)."""
    if n == 0:
        return [0.0, 1.0]
    p = successes / n
    denom  = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half   = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def cluster_bootstrap_f1_ci(
    scored: list[dict],
    n_iterations: int = 10000,
    seed: int = 42,
) -> list[float]:
    """95% CI for overall F1 from a cluster bootstrap over the eval ZIPs.

    Events cluster within 15 scripted recording sessions, so event-level
    intervals understate uncertainty. Resamples whole ZIPs with replacement
    (deterministic: random.Random(seed)) and takes the 2.5/97.5 percentiles.
    """
    from collections import defaultdict
    per_zip: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])  # tp, fp, fn
    for r in scored:
        cell = per_zip[r["source_zip"]]
        if r["ground_truth"] == "malicious":
            if _model_pred(r):
                cell[0] += 1
            else:
                cell[2] += 1
        elif _model_pred(r):
            cell[1] += 1

    zips = sorted(per_zip)
    rng  = random.Random(seed)
    f1_samples: list[float] = []
    for _ in range(n_iterations):
        tp = fp = fn = 0
        for name in rng.choices(zips, k=len(zips)):
            tp += per_zip[name][0]
            fp += per_zip[name][1]
            fn += per_zip[name][2]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_samples.append(2 * precision * recall / (precision + recall)
                          if (precision + recall) > 0 else 0.0)

    f1_samples.sort()
    lo = f1_samples[int(0.025 * (n_iterations - 1))]
    hi = f1_samples[int(0.975 * (n_iterations - 1))]
    return [round(lo, 4), round(hi, 4)]


def dedup_by_command_line(scored: list[dict]) -> dict:
    """Metrics after collapsing duplicate command lines within each class.

    Keeps the first occurrence of each (ground_truth, command_line) pair —
    checks whether within-session duplication inflates the point estimate.
    """
    seen: set[tuple[str, str]] = set()
    unique_rows: list[dict] = []
    for r in scored:
        key = (r["ground_truth"], r["command_line"] or "")
        if key not in seen:
            seen.add(key)
            unique_rows.append(r)
    out = _confusion(unique_rows, _model_pred)
    out["n_unique_malicious"] = sum(1 for r in unique_rows if r["ground_truth"] == "malicious")
    out["n_unique_benign"]    = len(unique_rows) - out["n_unique_malicious"]
    return out


def library_versions() -> dict[str, str]:
    """Exact library versions behind this run, embedded for reproducibility."""
    import platform
    import joblib
    import numpy
    import pandas
    import sklearn
    return {
        "python":       platform.python_version(),
        "scikit-learn": sklearn.__version__,
        "numpy":        numpy.__version__,
        "pandas":       pandas.__version__,
        "joblib":       joblib.__version__,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 68)
    print("LARGE INDEPENDENT EVALUATION — 15 ZIPs, 12 MITRE Techniques")
    print("=" * 68)

    # --- STEP 1: label (written before any model scoring) ---
    print("\nSTEP 1: Assigning ground-truth labels (technique semantics only) ...")
    labeled, load_stats, sequences = load_and_label()

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
    scored     = score_events(labeled, sequences, classifier)

    scores_path = OUT_DIR / "scores.json"
    scores_path.write_text(json.dumps(scored, indent=2))
    print(f"  Scores written → {scores_path}")

    # --- STEP 3: metrics ---
    print("\nSTEP 3: Computing metrics ...")
    metrics = compute_metrics(scored)

    # Overall
    all_mal = [r for r in scored if r["ground_truth"] == "malicious"]
    all_ben = [r for r in scored if r["ground_truth"] == "benign"]
    overall = {
        "n_malicious": len(all_mal),
        "n_benign":    len(all_ben),
        **_confusion(scored, _model_pred),
    }

    # --- STEP 4: baselines, uncertainty, funnel ---
    print("STEP 4: Computing baselines, confidence intervals, funnel ...")

    # Overall excluding T1047 (dominant single-ZIP technique) + macro recall
    non_t1047 = [r for r in scored if r["technique"] != "T1047"]
    overall_excl_t1047 = {
        "n_malicious": sum(1 for r in non_t1047 if r["ground_truth"] == "malicious"),
        "n_benign":    sum(1 for r in non_t1047 if r["ground_truth"] == "benign"),
        **_confusion(non_t1047, _model_pred),
    }
    recall_techs = [m for m in metrics.values() if m["n_malicious"] > 0]
    macro_recall = (round(sum(m["recall"] for m in recall_techs) / len(recall_techs), 4)
                    if recall_techs else 0.0)

    baselines    = compute_baselines(scored)
    agreement    = whitelist_agreement(scored)
    recall_ci    = wilson_ci(overall["tp"], overall["tp"] + overall["fn"])
    precision_ci = wilson_ci(overall["tp"], overall["tp"] + overall["fp"])
    f1_boot_ci   = cluster_bootstrap_f1_ci(scored)
    dedup        = dedup_by_command_line(scored)

    # Exclusion funnel (per-ZIP breakdown lives in load_stats)
    total_events = sum(s["total"] for s in load_stats.values())
    n_excluded   = sum(s["excluded"] for s in load_stats.values())
    exclusion_funnel = {
        "total_events_in_zips": total_events,
        "labeled":  total_events - n_excluded,
        "excluded": n_excluded,
        "exclusion_rate": round(n_excluded / total_events, 4) if total_events else 0.0,
    }

    results = {
        "library_versions": library_versions(),
        "config": {"p_star": P_STAR, "window_size": 10,
                   "context": "real preceding k=10 events per ZIP, recorded order"},
        "per_technique": metrics,
        "overall": overall,
        "overall_excluding_t1047": overall_excl_t1047,
        "macro_recall": macro_recall,
        "baselines": baselines,
        "model_vs_whitelist_rule": agreement,
        "uncertainty": {
            "recall_wilson_95ci":        recall_ci,
            "precision_wilson_95ci":     precision_ci,
            "f1_cluster_bootstrap_95ci": f1_boot_ci,
            "bootstrap": {"clusters": "eval ZIPs", "n_iterations": 10000, "seed": 42},
        },
        "dedup_by_command_line": dedup,
        "load_stats": load_stats,
        "exclusion_funnel": exclusion_funnel,
    }
    results_path = OUT_DIR / "results.json"
    results_path.write_text(json.dumps(results, indent=2))

    # --- Print summary ---
    lines = []
    lines.append("=" * 68)
    lines.append("LARGE INDEPENDENT EVALUATION RESULTS")
    lines.append(f"Threshold p* = {P_STAR}  |  Real k=10 context windows  |  No iteration on test set")
    lines.append("=" * 68)
    lines.append(f"\n{'Technique':<14} {'Tactic':<20} {'n_mal':>6} {'n_ben':>6} "
                 f"{'Prec':>6} {'Rec':>6} {'F1':>6} {'FN':>4} {'FP':>4}")
    lines.append("-" * 80)

    # Every technique in the manifest gets a row — none droppable by formatting
    manifest_tactics = {tech: tactic for _, tech, tactic in DATASETS}
    for tech in sorted(set(metrics) | set(manifest_tactics)):
        if tech in metrics:
            m = metrics[tech]
            lines.append(
                f"{tech:<14} {m['tactic']:<20} {m['n_malicious']:>6} {m['n_benign']:>6} "
                f"{m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} "
                f"{m['fn']:>4} {m['fp']:>4}"
            )
        else:
            lines.append(
                f"{tech:<14} {manifest_tactics[tech]:<20} {0:>6} {0:>6} "
                f"{'--':>6} {'--':>6} {'--':>6} {'--':>4} {'--':>4}  (no labeled events)"
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
    lines.append(f"  TP={overall['tp']}  FP={overall['fp']}  FN={overall['fn']}  TN={overall['tn']}")
    lines.append(f"Corpus funnel: {exclusion_funnel['total_events_in_zips']} events in ZIPs -> "
                 f"{exclusion_funnel['labeled']} labeled, {exclusion_funnel['excluded']} excluded "
                 f"({exclusion_funnel['exclusion_rate']:.1%} exclusion rate)")
    lines.append("")
    lines.append("Uncertainty:")
    lines.append(f"  Recall Wilson 95% CI:    [{recall_ci[0]:.3f}, {recall_ci[1]:.3f}]")
    lines.append(f"  Precision Wilson 95% CI: [{precision_ci[0]:.3f}, {precision_ci[1]:.3f}]")
    lines.append(f"  F1 cluster-bootstrap 95% CI (ZIPs resampled, 10000 iters, seed 42): "
                 f"[{f1_boot_ci[0]:.3f}, {f1_boot_ci[1]:.3f}]")
    lines.append("")
    lines.append(f"Overall excluding T1047: P={overall_excl_t1047['precision']:.3f} "
                 f"R={overall_excl_t1047['recall']:.3f} F1={overall_excl_t1047['f1']:.3f} "
                 f"(n_mal={overall_excl_t1047['n_malicious']})")
    lines.append(f"Macro-averaged recall over techniques: {macro_recall:.3f}")
    lines.append(f"Dedup by command line: P={dedup['precision']:.3f} R={dedup['recall']:.3f} "
                 f"F1={dedup['f1']:.3f} (n_mal={dedup['n_unique_malicious']}, "
                 f"n_ben={dedup['n_unique_benign']})")
    lines.append("")
    lines.append("Trivial baselines (same ground truth):")
    for name in ("always_malicious", "always_benign", "whitelist_21_process", "whitelist_3_process"):
        b = baselines[name]
        lines.append(f"  {name:<22} P={b['precision']:.3f} R={b['recall']:.3f} F1={b['f1']:.3f} "
                     f"(FP={b['fp']}, FN={b['fn']})")
    lines.append(f"Model vs 21-process whitelist rule agreement: "
                 f"{agreement['n_agree']}/{agreement['n_events']} "
                 f"({agreement['agreement_rate']:.1%})")
    lines.append("")
    train_stats_path = Path(__file__).resolve().parents[1] / "data" / "processed" / "train_stats.json"
    lines.append("Comparison to prior evaluations:")
    if train_stats_path.exists():
        train_stats = json.loads(train_stats_path.read_text(encoding="utf-8"))
        cv = train_stats.get("cv_logistic", {})
        lines.append(
            f"  CV F1 (in-distribution, n={train_stats.get('n_total', '?')}, circular labels): "
            f"{cv.get('f1', float('nan')):.3f}"
        )
    lines.append(f"  Independent eval (n=30, 5 techniques):   1.000  [CONTAMINATED — retracted]")
    lines.append(f"  This eval (n={len(scored)}, {len(metrics)} techniques, 15 ZIPs): {overall['f1']:.3f}")

    summary = "\n".join(lines)
    print("\n" + summary)
    summary_path = OUT_DIR / "summary.txt"
    summary_path.write_text(summary)
    print(f"\nFull results → {OUT_DIR}/")


if __name__ == "__main__":
    main()
