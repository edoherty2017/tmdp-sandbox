"""Data loading and feature extraction for security event log datasets.

Provides adapters for the three source formats used by this project:
  - logpai/loghub Windows_2k.log (benign system logs)
  - EVTX-ATTACK-SAMPLES JSON export (malicious attack event sequences)
  - securitydatasets.com JSON export (labeled security events)

All adapters normalize to EventSpec. Feature extraction produces flat
numeric/text dicts suitable for scikit-learn pipelines.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .context_window import (
    BaselineIntegrityResult,
    ContextWindowFeatures,
    check_baseline_integrity,
    extract_context_features,
)
from .event_spec import EventSpec


# ---------------------------------------------------------------------------
# Source adapters
# ---------------------------------------------------------------------------

def load_windows_2k_log(path: Path, label: str = "benign") -> list[EventSpec]:
    """Parse a logpai Windows_2k.log file into EventSpec list.

    Log format (space-separated):
        Date Time Level Component Content...
    Example:
        2016-09-28 04:30:30, Info CBS Loaded Servicing Stack...
    """
    events: list[EventSpec] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        component = parts[3] if len(parts) > 3 else ""
        content = parts[4] if len(parts) > 4 else line
        events.append(EventSpec(
            process_name=_normalize_process(component),
            command_line=content,
            user_name="SYSTEM",
            parent_process="",
            event_id=None,
            label=label,
            raw_log=line,
        ))
    return events


def load_otrf_dataset(path: Path, label: str = "malicious") -> list[EventSpec]:
    """Parse an OTRF/Security-Datasets JSONL file (or ZIP containing one) into EventSpec list.

    OTRF datasets use one JSON object per line. Fields use Windows event log naming
    conventions: EventID, NewProcessName/Image, CommandLine, SubjectUserName, etc.
    """
    if str(path).endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.endswith(".json") and not n.startswith("__")]
            if not names:
                return []
            with zf.open(names[0]) as f:
                text = f.read().decode("utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8", errors="replace")

    events: list[EventSpec] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue

        eid = _parse_event_id(item.get("EventID"))

        # Sysmon EventID 10: process access (SourceImage → TargetImage)
        # Map TargetImage into parent_process, GrantedAccess into command_line
        if eid == 10:
            process_name = _normalize_process(item.get("SourceImage", ""))
            parent_process = _normalize_process(item.get("TargetImage", ""))
            granted = item.get("GrantedAccess", "")
            target = item.get("TargetImage", "")
            command_line = f"access {target} flags={granted}"
            user_name = str(item.get("SourceUser") or item.get("User") or "")
        # Sysmon EventID 12/13: registry create/delete/set
        elif eid in (12, 13):
            process_name = _normalize_process(item.get("Image", ""))
            parent_process = ""
            target_obj = item.get("TargetObject", "")
            details = item.get("Details", "")
            event_type = item.get("EventType", "")
            command_line = f"reg {event_type} {target_obj}={details}"[:500]
            user_name = str(item.get("User") or "")
        # Sysmon EventID 7: image (DLL) loaded
        elif eid == 7:
            process_name = _normalize_process(item.get("Image", ""))
            parent_process = ""
            img_loaded = item.get("ImageLoaded", "")
            signed = item.get("Signed", "true")
            sig = item.get("Signature", "")
            command_line = f"load {img_loaded} signed={signed} sig={sig}"[:500]
            user_name = str(item.get("User") or "")
        else:
            # Process name: Sysmon uses Image, Windows Security uses NewProcessName
            process_name = _normalize_process(
                item.get("Image") or item.get("NewProcessName") or
                item.get("ProcessName") or item.get("SourceName") or ""
            )
            # Command line
            command_line = (
                item.get("CommandLine") or item.get("ParentCommandLine") or
                item.get("ScriptBlockText") or item.get("Message") or ""
            )
            # User
            user_name = (
                item.get("SubjectUserName") or item.get("User") or
                item.get("TargetUserName") or ""
            )
            # Parent process
            parent_process = _normalize_process(
                item.get("ParentImage") or item.get("ParentProcessName") or
                item.get("CallerProcessName") or ""
            )

        events.append(EventSpec(
            process_name=process_name,
            command_line=str(command_line)[:500],
            user_name=str(user_name),
            parent_process=parent_process,
            event_id=eid,
            label=label,
            raw_log=line[:300],
        ))
    return events


def load_evtx_attack_json(path: Path, label: str = "malicious") -> list[EventSpec]:
    """Alias for load_otrf_dataset for backward compatibility."""
    return load_otrf_dataset(path, label=label)


def load_security_dataset_json(path: Path) -> list[EventSpec]:
    """Parse a securitydatasets.com JSON export.

    These datasets typically include a 'Label' or 'label' field per event.
    Missing labels default to 'benign'.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("events", raw.get("data", []))
    events: list[EventSpec] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        item_lower = {k.lower(): v for k, v in item.items()}
        raw_label = str(item_lower.get("label", "benign")).lower()
        label = "malicious" if raw_label in {"malicious", "attack", "1", "true"} else "benign"
        events.append(EventSpec(
            process_name=_normalize_process(
                str(item_lower.get("processname", item_lower.get("process_name", "")))
            ),
            command_line=str(item_lower.get("commandline", item_lower.get("command_line", ""))),
            user_name=str(item_lower.get("username", item_lower.get("user_name", ""))),
            parent_process=_normalize_process(
                str(item_lower.get("parentprocessname", item_lower.get("parent_process", "")))
            ),
            event_id=_parse_event_id(item_lower.get("eventid", item_lower.get("event_id"))),
            label=label,
            raw_log=json.dumps(item),
        ))
    return events


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(
    event: EventSpec,
    context: ContextWindowFeatures,
    integrity: BaselineIntegrityResult,
) -> dict[str, Any]:
    """Produce a flat feature dict for one event + its context.

    The returned dict has two kinds of keys:
    - "text__*": string values for TF-IDF / text vectorizers
    - numeric keys: float/int values for numeric transformers

    Keeps the label OUT of the feature dict. The caller is responsible for
    separately extracting labels from EventSpec.label.
    """
    return {
        # Text features (fed to TF-IDF)
        "text__command_line": event.command_line,
        "text__process_name": event.process_name,
        "text__parent_process": event.parent_process,

        # Baseline integrity (Phase 1)
        "feat__in_baseline": float(integrity.in_baseline),
        "feat__is_suspicious_process": float(integrity.is_suspicious_process),
        "feat__has_obfuscated_command": float(integrity.has_obfuscated_command),
        # EID-10 access mask: PROCESS_VM_READ (0x0010) present in GrantedAccess.
        # Shares GrantedAccess parsing with auto_label_event so rule and feature
        # cannot drift.
        "feat__has_vm_read": float(integrity.has_vm_read),

        # Event metadata
        "feat__event_id": float(event.event_id) if event.event_id is not None else -1.0,
        # Set-membership flag: True for EIDs that are definitively attack indicators regardless
        # of which process fires them (EID 4698=scheduled task created, 1102=log cleared, etc.)
        "feat__is_attack_eid": float(
            event.event_id is not None and event.event_id in _ATTACK_EVENT_IDS
        ),
        "feat__is_system_user": float(
            event.user_name.upper() in {"SYSTEM", "NT AUTHORITY\\SYSTEM", "LOCAL SERVICE"}
        ),

        # Context window (Phase 1)
        "feat__ctx_suspicious_proc_count": float(context.suspicious_process_count),
        "feat__ctx_suspicious_eid_count": float(context.suspicious_event_id_count),
        "feat__ctx_obfuscated_count": float(context.obfuscated_command_count),
        "feat__ctx_unique_processes": float(context.unique_processes),
        "feat__ctx_system_ratio": context.system_account_ratio,
        "feat__ctx_log_cleared": float(context.log_cleared_in_window),
        "feat__ctx_window_size": float(context.window_size),
    }


def extract_features_for_sequence(
    events: list[EventSpec] | tuple[EventSpec, ...],
    window_size: int = 10,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract features and labels for all events in a sequence.

    Returns (feature_dicts, labels) where labels[i] is events[i].label.
    Context window for event i covers events[max(0, i-window_size):i].
    """
    feature_dicts: list[dict[str, Any]] = []
    labels: list[str] = []
    events_tuple = tuple(events)
    for i, event in enumerate(events_tuple):
        context = extract_context_features(events_tuple, i, window_size=window_size)
        integrity = check_baseline_integrity(event)
        feature_dicts.append(extract_features(event, context, integrity))
        labels.append(event.label)
    return feature_dicts, labels


# ---------------------------------------------------------------------------
# OTRF auto-labeling
# ---------------------------------------------------------------------------

# EventIDs whose presence alone indicates attack activity
_ATTACK_EVENT_IDS: frozenset[int] = frozenset({1102, 4697, 4698, 4702, 4720, 4732, 7045})
# Sysmon + Windows Security process-creation event IDs
_PROCESS_CREATE_EIDS: frozenset[int] = frozenset({1, 4688})
# Patterns that indicate obfuscated / encoded execution
_OBFUSCATION_RE = re.compile(
    r"-[eE][nN][cC]|-encodedcommand|iex\s*\(|invoke-expression|"
    r"downloadstring|downloadfile|-executionpolicy\s+bypass|"
    r"-bypass|bypass\s+unrestricted|http[s]?://|"
    r"[A-Za-z0-9+/]{40,}={0,2}",
    re.IGNORECASE,
)
# Registry paths associated with persistence / defense-evasion / UAC bypass
_PERSISTENCE_RE = re.compile(
    r"\\Run\\|\\RunOnce\\|\\Services\\|\\ControlSet.*\\Services\\"
    r"|\\CurrentVersion\\Image File Execution|\\Winlogon\\"
    r"|\\SecurityProviders\\|\\lsa\\"
    # UAC bypass via shell handler hijack (fodhelper, eventvwr, sdclt, etc.)
    r"|\\shell\\open\\command|\\ms-settings\\|\\mscfile\\"
    r"|\\Classes\\.*\\shell\\",
    re.IGNORECASE,
)
# Process access targets that indicate credential theft
_CRED_THEFT_TARGETS: frozenset[str] = frozenset({"lsass.exe", "winlogon.exe", "sam"})


def auto_label_event(event: "EventSpec") -> str | None:
    """Assign malicious/benign label from Sysmon/Security event properties.

    Returns None for ambiguous events that should be excluded from training.

    Labeling strategy:
    - Malicious: LOLBin process creation, dump-capable lsass process access
      (PROCESS_VM_READ mask, non-baseline/non-agent source), persistence
      registry writes, unsigned DLL loads by suspicious processes.
    - Benign: known-good process creation without obfuscation, normal registry
      ops by baseline processes, signed Microsoft DLL loads.
    - None: insufficient signal — exclude from training set.
    """
    from .context_window import (
        _AGENT_PROCESSES,
        _BASELINE_PROCESSES,
        _SUSPICIOUS_PROCESSES,
        has_vm_read,
    )

    eid = event.event_id
    proc = event.process_name.lower()
    cmd = event.command_line.lower()

    if eid in _ATTACK_EVENT_IDS:
        return "malicious"

    # PowerShell script block logging: any obfuscation in the script text = malicious
    if eid in (4103, 4104):
        if _OBFUSCATION_RE.search(cmd):
            return "malicious"
        return None  # unobfuscated blocks are ambiguous

    if eid in _PROCESS_CREATE_EIDS:
        if proc in _SUSPICIOUS_PROCESSES:
            return "malicious"
        if proc in _BASELINE_PROCESSES and not _OBFUSCATION_RE.search(cmd):
            return "benign"
        return None

    if eid == 10:
        target = event.parent_process.lower()
        if any(t in target for t in _CRED_THEFT_TARGETS):
            # Credential theft requires a dump-capable GrantedAccess mask
            # (PROCESS_VM_READ 0x0010) from a non-baseline, non-agent source.
            # QUERY-only masks (e.g. 0x1400) are routine housekeeping polls by
            # hypervisor/AV agents — ambiguous regardless of source.
            if (
                has_vm_read(event)
                and proc not in _BASELINE_PROCESSES
                and proc not in _AGENT_PROCESSES
            ):
                return "malicious"
            return None
        if proc in _BASELINE_PROCESSES:
            return "benign"
        return None

    if eid in (12, 13):
        if _PERSISTENCE_RE.search(cmd) and proc in _SUSPICIOUS_PROCESSES:
            return "malicious"
        if proc in _BASELINE_PROCESSES:
            return "benign"
        return None

    if eid == 7:
        if "signed=false" in cmd and proc in _SUSPICIOUS_PROCESSES:
            return "malicious"
        if "signed=true" in cmd and "microsoft" in cmd and proc in _BASELINE_PROCESSES:
            return "benign"
        return None

    if proc in _SUSPICIOUS_PROCESSES and _OBFUSCATION_RE.search(cmd):
        return "malicious"

    return None


def load_otrf_labeled_pool(
    malicious_dir: Path,
) -> tuple[list["EventSpec"], list["EventSpec"]]:
    """Load all OTRF ZIPs from malicious_dir and auto-label events.

    Returns (benign_pool, malicious_pool). Ambiguous events are discarded.
    Suitable for use in training and batch experiment scripts.
    """
    import dataclasses

    benign_pool: list[EventSpec] = []
    malicious_pool: list[EventSpec] = []

    for zf in sorted(Path(malicious_dir).glob("*.zip")):
        for event in load_otrf_dataset(zf, label="malicious"):
            lbl = auto_label_event(event)
            if lbl is None:
                continue
            labeled = dataclasses.replace(event, label=lbl)
            if lbl == "benign":
                benign_pool.append(labeled)
            else:
                malicious_pool.append(labeled)

    return benign_pool, malicious_pool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_process(name: str) -> str:
    """Lowercase and strip path prefix from process names."""
    name = name.strip().lower()
    if "\\" in name:
        name = name.rsplit("\\", 1)[-1]
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    return name


def _parse_event_id(raw: Any) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None
