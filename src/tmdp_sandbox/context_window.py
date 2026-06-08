"""Phase 1: baseline integrity check and context-window feature extraction.

The baseline integrity checker flags commands that are not in the known-good
whitelist. The context window extractor computes aggregate suspicion features
over the N events preceding the current decision point.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .event_spec import EventSpec

# Processes that are almost always benign in normal Windows operation.
_BASELINE_PROCESSES = frozenset({
    "svchost.exe", "explorer.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "csrss.exe", "wininit.exe", "smss.exe", "taskhostw.exe",
    "spoolsv.exe", "searchindexer.exe", "conhost.exe", "dwm.exe",
    "runtimebroker.exe", "system", "registry", "ntoskrnl.exe",
    "audiodg.exe", "wuauclt.exe", "msiexec.exe", "dllhost.exe",
})

# Processes commonly abused in living-off-the-land attacks.
_SUSPICIOUS_PROCESSES = frozenset({
    "cmd.exe", "powershell.exe", "powershell_ise.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe", "net.exe", "net1.exe",
    "sc.exe", "reg.exe", "at.exe", "schtasks.exe", "psexec.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "odbcconf.exe", "pcalua.exe", "cmstp.exe",
    # UAC-bypass launchers: these processes only appear in elevated context
    # when their COM handler or shell association has been hijacked.
    "fodhelper.exe", "eventvwr.exe", "sdclt.exe", "slui.exe",
    "computerdefaults.exe", "wsreset.exe",
    # Post-exploitation reconnaissance tools
    "whoami.exe", "ipconfig.exe", "nltest.exe", "klist.exe",
})

# Windows event IDs associated with attacker-relevant activity.
_SUSPICIOUS_EVENT_IDS = frozenset({
    1102,   # Audit log cleared
    4698,   # Scheduled task created
    4702,   # Scheduled task updated
    4720,   # User account created
    4732,   # Member added to local security group
    4672,   # Special privileges assigned to new logon
    4697,   # Service installed
    7045,   # New service installed (System log)
    4625,   # Failed logon
    4648,   # Logon with explicit credentials
    4688,   # Process creation (high-signal when combined with suspicious process)
})

# Patterns in command lines that indicate encoded/obfuscated execution.
_OBFUSCATION_PATTERNS = [
    re.compile(r"-[eE][nN][cC]", re.IGNORECASE),          # powershell -enc
    re.compile(r"-[eE]ncodedCommand", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),               # long base64
    re.compile(r"iex\s*\(", re.IGNORECASE),                 # Invoke-Expression
    re.compile(r"invoke-expression", re.IGNORECASE),
    re.compile(r"downloadstring|downloadfile|webclient", re.IGNORECASE),
    re.compile(r"http[s]?://", re.IGNORECASE),              # download URLs
    re.compile(r"-noprofile|-nop\b", re.IGNORECASE),        # bypass profile
    re.compile(r"-executionpolicy\s+bypass", re.IGNORECASE),
    re.compile(r"bypass|unrestricted", re.IGNORECASE),
]


@dataclass(frozen=True)
class BaselineIntegrityResult:
    process_name: str
    in_baseline: bool
    is_suspicious_process: bool
    has_obfuscated_command: bool


@dataclass(frozen=True)
class ContextWindowFeatures:
    window_size: int
    suspicious_process_count: int
    suspicious_event_id_count: int
    obfuscated_command_count: int
    unique_processes: int
    system_account_ratio: float
    log_cleared_in_window: bool


def check_baseline_integrity(event: EventSpec) -> BaselineIntegrityResult:
    """Phase 1 baseline integrity check for a single event."""
    proc = event.process_name.lower()
    return BaselineIntegrityResult(
        process_name=proc,
        in_baseline=proc in _BASELINE_PROCESSES,
        is_suspicious_process=proc in _SUSPICIOUS_PROCESSES,
        has_obfuscated_command=_has_obfuscation(event.command_line),
    )


def extract_context_features(
    events: tuple[EventSpec, ...],
    decision_index: int,
    window_size: int = 10,
) -> ContextWindowFeatures:
    """Phase 1 context-window feature extraction.

    Examines the `window_size` events preceding `decision_index` and returns
    aggregate suspicion indicators. The decision event itself is not included
    in the window — those features come from the event directly.
    """
    start = max(0, decision_index - window_size)
    window = events[start:decision_index]

    suspicious_proc = sum(
        1 for e in window if e.process_name.lower() in _SUSPICIOUS_PROCESSES
    )
    suspicious_eid = sum(
        1 for e in window if e.event_id in _SUSPICIOUS_EVENT_IDS
    )
    obfuscated = sum(1 for e in window if _has_obfuscation(e.command_line))
    unique_procs = len({e.process_name.lower() for e in window})
    system_count = sum(
        1 for e in window
        if e.user_name.upper() in {"SYSTEM", "NT AUTHORITY\\SYSTEM", "LOCAL SERVICE"}
    )
    system_ratio = system_count / len(window) if window else 0.0
    log_cleared = any(e.event_id == 1102 for e in window)

    return ContextWindowFeatures(
        window_size=len(window),
        suspicious_process_count=suspicious_proc,
        suspicious_event_id_count=suspicious_eid,
        obfuscated_command_count=obfuscated,
        unique_processes=unique_procs,
        system_account_ratio=system_ratio,
        log_cleared_in_window=log_cleared,
    )


def _has_obfuscation(command_line: str) -> bool:
    return any(pat.search(command_line) for pat in _OBFUSCATION_PATTERNS)
