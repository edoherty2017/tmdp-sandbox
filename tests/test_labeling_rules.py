"""Regression tests pinning the corrected EID-10 process-access labeling rule.

The 2026-07-21 adversarial review (finding F8) showed the original source- and
mask-blind rule labeled 438/618 (70.9%) of the malicious training pool as
attacks when they were routine VirtualBox Guest Additions housekeeping polls
(vboxservice.exe opening a QUERY-only 0x1400 handle to lsass.exe). These tests
freeze the corrected behavior so the mislabel cannot silently return:

    malicious  iff  target is a credential store
                    AND the GrantedAccess mask includes PROCESS_VM_READ (0x0010)
                    AND the source process is neither baseline nor a known agent
    None (excluded) for QUERY-only masks, agent/baseline sources, or absent masks
"""

from tmdp_sandbox.event_spec import EventSpec
from tmdp_sandbox.preprocessing import auto_label_event


def _access(
    source: str,
    target: str = "lsass.exe",
    granted: str = "0x1400",
) -> EventSpec:
    """Build a Sysmon EID-10 process-access event in the adapter's shape.

    The loader maps SourceImage -> process_name, TargetImage -> parent_process,
    and GrantedAccess into the command line as ``access <target> flags=<mask>``.
    """
    return EventSpec(
        process_name=source,
        command_line=f"access {target} flags={granted}",
        user_name="SYSTEM",
        parent_process=target,
        event_id=10,
    )


# --- The exact regression the review exposed ---------------------------------

def test_vboxservice_query_only_poll_is_not_malicious():
    """The 438-event mislabel: VBox agent, lsass target, QUERY-only 0x1400."""
    assert auto_label_event(_access("vboxservice.exe", "lsass.exe", "0x1400")) is None


def test_defender_query_only_poll_is_not_malicious():
    """msmpeng.exe (Windows Defender) polling lsass is agent housekeeping too."""
    assert auto_label_event(_access("msmpeng.exe", "lsass.exe", "0x1400")) is None


# --- The mask must actually be dump-capable ----------------------------------

def test_query_only_mask_from_unknown_source_is_excluded_not_malicious():
    """0x1400 lacks PROCESS_VM_READ, so even an unknown source is ambiguous."""
    assert auto_label_event(_access("unknown.exe", "lsass.exe", "0x1400")) is None


def test_vm_read_mask_from_non_agent_source_is_malicious():
    """0x1410 includes PROCESS_VM_READ (0x0010) — a dump-capable handle."""
    assert auto_label_event(_access("mimikatz.exe", "lsass.exe", "0x1410")) == "malicious"


def test_process_all_access_mask_is_malicious():
    """A broad 0x1fffff mask includes PROCESS_VM_READ."""
    assert auto_label_event(_access("rundll32.exe", "lsass.exe", "0x1fffff")) == "malicious"


def test_missing_mask_is_excluded():
    """No parseable GrantedAccess -> cannot confirm dump capability -> excluded."""
    ev = EventSpec(
        process_name="unknown.exe",
        command_line="access lsass.exe",
        user_name="SYSTEM",
        parent_process="lsass.exe",
        event_id=10,
    )
    assert auto_label_event(ev) is None


# --- Source gating: agent/baseline sources are never malicious ---------------

def test_agent_source_with_dump_mask_is_still_excluded():
    """Even a VM_READ mask is excluded when the source is a known agent."""
    assert auto_label_event(_access("vboxservice.exe", "lsass.exe", "0x1410")) is None


def test_baseline_source_with_dump_mask_is_excluded():
    """A baseline system process reading lsass is excluded, not flagged."""
    assert auto_label_event(_access("svchost.exe", "lsass.exe", "0x1410")) is None


# --- Target gating: only credential stores trigger the malicious branch -------

def test_dump_mask_against_noncred_target_is_not_malicious():
    """PROCESS_VM_READ against a non-credential target is not the attack signal."""
    result = auto_label_event(_access("someapp.exe", "notepad.exe", "0x1410"))
    assert result != "malicious"


def test_winlogon_and_sam_are_credential_targets():
    """winlogon.exe and the SAM store are credential targets alongside lsass."""
    assert auto_label_event(_access("mimikatz.exe", "winlogon.exe", "0x1410")) == "malicious"
    assert auto_label_event(_access("mimikatz.exe", "sam", "0x1410")) == "malicious"


# --- Whole-pool guard: agent polls must not dominate the malicious class ------

def test_agent_poll_batch_contributes_zero_malicious():
    """A burst of agent polls (the original 438-event failure mode) yields none."""
    polls = [_access("vboxservice.exe", "lsass.exe", "0x1400") for _ in range(50)]
    assert sum(auto_label_event(e) == "malicious" for e in polls) == 0
