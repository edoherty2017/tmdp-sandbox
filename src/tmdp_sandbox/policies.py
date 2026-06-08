"""Baseline scripted policies for deterministic sandbox experiments."""

from __future__ import annotations

from .classifier import MLCommandClassifier
from .context_window import check_baseline_integrity, extract_context_features
from .event_spec import SecurityScenario
from .risk import DeleteRiskAssessor, ObservableFeatureRiskAssessor, OracleLabelRiskAssessor
from .risk_noise import calibrated_inspection_observations
from .runner import ScriptedPolicy
from .scenario import SandboxScenario
from .security_runner import SecurityScriptedPolicy
from .tmdp_model import RiskBin, TMDPModel
from .value_iteration import greedy_action, value_iteration


def build_baseline_policy(
    name: str,
    scenario: SandboxScenario,
    *,
    risk_threshold: float = 0.5,
    risk_assessor: DeleteRiskAssessor | None = None,
) -> ScriptedPolicy:
    """Build an initial deterministic baseline policy for a scenario."""

    assessor = (
        risk_assessor
        if risk_assessor is not None
        else ObservableFeatureRiskAssessor()
        if name == "observable-threshold-risk"
        else OracleLabelRiskAssessor()
    )

    if name == "always-terminate":
        return ScriptedPolicy(
            policy_id=name,
            outputs=("TERMINATE baseline always terminates",),
            risk_estimates=(0.0,),
        )

    by_path = {spec.path: spec for spec in scenario.files}
    requested_files = tuple(by_path[path] for path in scenario.requested_deletions)
    if name == "no-termination":
        assessments = tuple(
            assessor.assess_delete(scenario=scenario, path=spec.path) for spec in requested_files
        )
        return ScriptedPolicy(
            policy_id=name,
            outputs=tuple(f"DELETE {spec.path}" for spec in requested_files),
            risk_estimates=tuple(assessment.score for assessment in assessments),
        )

    if name in {"threshold-risk", "observable-threshold-risk"}:
        outputs: list[str] = []
        risks: list[float] = []
        for spec in requested_files:
            risk = assessor.assess_delete(scenario=scenario, path=spec.path).score
            if risk > risk_threshold:
                outputs.append("TERMINATE risk threshold exceeded")
                risks.append(risk)
                return ScriptedPolicy(
                    policy_id=name,
                    outputs=tuple(outputs),
                    risk_estimates=tuple(risks),
                )
            outputs.append(f"DELETE {spec.path}")
            risks.append(risk)
        outputs.append("TERMINATE threshold cleanup complete")
        risks.append(0.0)
        return ScriptedPolicy(policy_id=name, outputs=tuple(outputs), risk_estimates=tuple(risks))

    raise ValueError(f"unknown baseline policy: {name!r}")


def build_tmdp_value_iteration_policy(
    scenario: SandboxScenario,
    *,
    observable_risk_by_path: dict[str, RiskBin],
    p_catastrophic_by_path: dict[str, float],
    inspection_observations_by_path: dict[str, dict[RiskBin, tuple[float, float]]] | None = None,
    catastrophe_cost: float = 100.0,
    termination_cost: float = 5.0,
    delete_step_cost: float = 1.0,
    inspect_step_cost: float = 0.25,
    completion_cost: float = 0.0,
) -> ScriptedPolicy:
    """Build the first finite-state value-iteration policy adapter.

    This milestone-1 adapter evaluates requested deletions in order with a
    one-step belief-state T-MDP per candidate. It consumes observable risk bins
    and catastrophe beliefs; it does not read hidden fixture labels when
    constructing the Bellman model.
    """

    by_path = {spec.path: spec for spec in scenario.files}
    outputs: list[str] = []
    risks: list[float] = []
    for target_path in scenario.requested_deletions:
        if target_path not in by_path:
            raise ValueError(f"requested deletion not present in fixture files: {target_path!r}")
        if target_path not in observable_risk_by_path:
            raise ValueError(f"missing observable risk bin for requested deletion: {target_path!r}")
        if target_path not in p_catastrophic_by_path:
            raise ValueError(f"missing catastrophe belief for requested deletion: {target_path!r}")

        inspection_observations = (
            inspection_observations_by_path.get(target_path)
            if inspection_observations_by_path is not None
            else None
        )
        model = TMDPModel.single_candidate(
            p_catastrophic=p_catastrophic_by_path[target_path],
            observable_risk_bin=observable_risk_by_path[target_path],
            inspection_observations=inspection_observations,
            catastrophe_cost=catastrophe_cost,
            termination_cost=termination_cost,
            delete_step_cost=delete_step_cost,
            inspect_step_cost=inspect_step_cost,
            completion_cost=completion_cost,
        )
        _, policy = value_iteration(model)
        action = greedy_action(policy, model.initial_state)
        risks.append(p_catastrophic_by_path[target_path])
        if action == "DELETE_NEXT":
            outputs.append(f"DELETE {target_path}")
            continue
        if action == "TERMINATE":
            outputs.append("TERMINATE tmdp expected-cost policy")
            return ScriptedPolicy(
                policy_id="tmdp-value-iteration",
                outputs=tuple(outputs),
                risk_estimates=tuple(risks),
            )
        outputs.append("TERMINATE tmdp inspect action not supported by scripted runner")
        return ScriptedPolicy(
            policy_id="tmdp-value-iteration",
            outputs=tuple(outputs),
            risk_estimates=tuple(risks),
        )

    return ScriptedPolicy(
        policy_id="tmdp-value-iteration",
        outputs=tuple(outputs) if outputs else ("TERMINATE tmdp no requested deletions",),
        risk_estimates=tuple(risks) if risks else (0.0,),
    )


def build_security_tmdp_policy(
    scenario: SecurityScenario,
    *,
    classifier: MLCommandClassifier,
    compromise_cost: float = 100.0,
    block_cost: float = 5.0,
    execute_step_cost: float = 1.0,
    defer_step_cost: float = 0.25,
    inspection_delta: float = 0.2,
    risk_noise_sigma: float = 0.0,
) -> SecurityScriptedPolicy:
    """Build a Phase 1 + 2 + 3 security policy for one scenario.

    For each requested execution:
      Phase 1 — extract context window and baseline integrity features
      Phase 2 — query MLCommandClassifier for P(malicious)
      Phase 3 — run T-MDP value iteration; emit EXECUTE, BLOCK, or DEFER
    """
    from .risk_noise import apply_noise

    outputs: list[str] = []
    risks: list[float] = []

    for step, event_idx in enumerate(scenario.requested_executions):
        event = scenario.events[event_idx]
        p_malicious = classifier.score_event(
            event, scenario.events, decision_index=event_idx
        )
        if risk_noise_sigma > 0.0:
            p_malicious = apply_noise(
                base_score=p_malicious,
                seed=scenario.seed + step,
                sigma=risk_noise_sigma,
            )

        observable_risk_bin: RiskBin = _risk_bin(p_malicious)
        inspection_observations = calibrated_inspection_observations(
            p_malicious, delta=inspection_delta
        )

        model = TMDPModel.single_candidate(
            p_catastrophic=p_malicious,
            observable_risk_bin=observable_risk_bin,
            inspection_observations=inspection_observations,
            catastrophe_cost=compromise_cost,
            termination_cost=block_cost,
            delete_step_cost=execute_step_cost,
            inspect_step_cost=defer_step_cost,
            completion_cost=0.0,
        )
        _, policy = value_iteration(model)
        action = greedy_action(policy, model.initial_state)
        risks.append(p_malicious)

        if action == "DELETE_NEXT":
            outputs.append(f"EXECUTE {event_idx}")
        elif action == "TERMINATE":
            outputs.append("BLOCK security-tmdp policy")
            return SecurityScriptedPolicy(
                policy_id="security-tmdp-value-iteration",
                outputs=tuple(outputs),
                risk_estimates=tuple(risks),
            )
        else:  # INSPECT_NEXT → DEFER
            outputs.append(f"DEFER {event_idx}")

    return SecurityScriptedPolicy(
        policy_id="security-tmdp-value-iteration",
        outputs=tuple(outputs) if outputs else ("BLOCK security-tmdp no events",),
        risk_estimates=tuple(risks) if risks else (0.0,),
    )


def build_security_threshold_policy(
    scenario: SecurityScenario,
    *,
    classifier: MLCommandClassifier,
    block_threshold: float = 0.5,
    risk_noise_sigma: float = 0.0,
) -> SecurityScriptedPolicy:
    """Scripted threshold baseline: block on first event exceeding threshold."""
    from .risk_noise import apply_noise

    outputs: list[str] = []
    risks: list[float] = []

    for step, event_idx in enumerate(scenario.requested_executions):
        event = scenario.events[event_idx]
        p_malicious = classifier.score_event(
            event, scenario.events, decision_index=event_idx
        )
        if risk_noise_sigma > 0.0:
            p_malicious = apply_noise(
                base_score=p_malicious,
                seed=scenario.seed + step,
                sigma=risk_noise_sigma,
            )
        risks.append(p_malicious)
        if p_malicious > block_threshold:
            outputs.append("BLOCK threshold exceeded")
            return SecurityScriptedPolicy(
                policy_id="security-threshold",
                outputs=tuple(outputs),
                risk_estimates=tuple(risks),
            )
        outputs.append(f"EXECUTE {event_idx}")

    outputs.append("BLOCK threshold cleanup complete")
    risks.append(0.0)
    return SecurityScriptedPolicy(
        policy_id="security-threshold",
        outputs=tuple(outputs),
        risk_estimates=tuple(risks),
    )


def build_security_sequential_policy(
    scenario: SecurityScenario,
    *,
    classifier: MLCommandClassifier,
    compromise_cost: float = 100.0,
    block_cost: float = 5.0,
    execute_step_cost: float = 1.0,
    defer_step_cost: float = 0.25,
    inspection_delta: float = 0.2,
    risk_noise_sigma: float = 0.0,
) -> SecurityScriptedPolicy:
    """Sequential block policy: BLOCK_EVENT per suspicious event, episode never stops early.

    Identical T-MDP value iteration per event, but when the T-MDP chooses TERMINATE,
    the policy emits BLOCK_EVENT (blocks this one event, continues) rather than BLOCK
    (which terminates the entire episode). This lets benign events after a malicious
    detection still execute, improving benign_allow_rate at no safety cost.
    """
    from .risk_noise import apply_noise

    outputs: list[str] = []
    risks: list[float] = []

    for step, event_idx in enumerate(scenario.requested_executions):
        event = scenario.events[event_idx]
        p_malicious = classifier.score_event(
            event, scenario.events, decision_index=event_idx
        )
        if risk_noise_sigma > 0.0:
            p_malicious = apply_noise(
                base_score=p_malicious,
                seed=scenario.seed + step,
                sigma=risk_noise_sigma,
            )

        observable_risk_bin: RiskBin = _risk_bin(p_malicious)
        inspection_observations = calibrated_inspection_observations(
            p_malicious, delta=inspection_delta
        )

        model = TMDPModel.single_candidate(
            p_catastrophic=p_malicious,
            observable_risk_bin=observable_risk_bin,
            inspection_observations=inspection_observations,
            catastrophe_cost=compromise_cost,
            termination_cost=block_cost,
            delete_step_cost=execute_step_cost,
            inspect_step_cost=defer_step_cost,
            completion_cost=0.0,
        )
        _, policy = value_iteration(model)
        action = greedy_action(policy, model.initial_state)
        risks.append(p_malicious)

        if action == "DELETE_NEXT":
            outputs.append(f"EXECUTE {event_idx}")
        elif action == "TERMINATE":
            outputs.append(f"BLOCK_EVENT {event_idx}")  # block this event, continue
        else:  # INSPECT_NEXT → DEFER
            outputs.append(f"DEFER {event_idx}")

    return SecurityScriptedPolicy(
        policy_id="security-tmdp-sequential",
        outputs=tuple(outputs) if outputs else ("BLOCK_EVENT 0",),
        risk_estimates=tuple(risks) if risks else (0.0,),
    )


def build_security_tmdp_no_defer_policy(
    scenario: SecurityScenario,
    *,
    classifier: MLCommandClassifier,
    compromise_cost: float = 100.0,
    block_cost: float = 5.0,
    execute_step_cost: float = 1.0,
    risk_noise_sigma: float = 0.0,
) -> SecurityScriptedPolicy:
    """T-MDP policy that treats INSPECT_NEXT as BLOCK (no human-deferral available).

    Identical to build_security_tmdp_policy except that degenerate inspection
    observations are passed so value iteration never chooses INSPECT_NEXT.
    Comparing this against build_security_tmdp_policy isolates the value of DEFER.
    """
    from .risk_noise import apply_noise

    outputs: list[str] = []
    risks: list[float] = []

    for step, event_idx in enumerate(scenario.requested_executions):
        event = scenario.events[event_idx]
        p_malicious = classifier.score_event(
            event, scenario.events, decision_index=event_idx
        )
        if risk_noise_sigma > 0.0:
            p_malicious = apply_noise(
                base_score=p_malicious,
                seed=scenario.seed + step,
                sigma=risk_noise_sigma,
            )

        observable_risk_bin: RiskBin = _risk_bin(p_malicious)
        # Degenerate observations → inspection gives no information → VI never defers
        model = TMDPModel.single_candidate(
            p_catastrophic=p_malicious,
            observable_risk_bin=observable_risk_bin,
            inspection_observations=None,
            catastrophe_cost=compromise_cost,
            termination_cost=block_cost,
            delete_step_cost=execute_step_cost,
            inspect_step_cost=0.25,
            completion_cost=0.0,
        )
        _, policy = value_iteration(model)
        action = greedy_action(policy, model.initial_state)
        risks.append(p_malicious)

        if action == "DELETE_NEXT":
            outputs.append(f"EXECUTE {event_idx}")
        else:
            outputs.append("BLOCK security-tmdp-nodefer policy")
            return SecurityScriptedPolicy(
                policy_id="security-tmdp-nodefer",
                outputs=tuple(outputs),
                risk_estimates=tuple(risks),
            )

    return SecurityScriptedPolicy(
        policy_id="security-tmdp-nodefer",
        outputs=tuple(outputs) if outputs else ("BLOCK security-tmdp-nodefer no events",),
        risk_estimates=tuple(risks) if risks else (0.0,),
    )


def _risk_score(risk_bin: RiskBin) -> float:
    return {"low": 0.1, "medium": 0.5, "high": 0.9}[risk_bin]


def _risk_bin(p: float) -> RiskBin:
    """Map a probability to the nearest RiskBin label."""
    if p < 0.35:
        return "low"
    if p < 0.65:
        return "medium"
    return "high"
