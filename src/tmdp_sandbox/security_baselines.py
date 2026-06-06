"""Security-log baseline policies and batch experiment runner."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .security_log import (
    SecurityLogScenario,
    SecurityPolicy,
    load_security_scenario_file,
    run_security_episode,
    summarize_security_results,
)


@dataclass(frozen=True)
class SecurityBatchResult:
    episodes: int
    aggregate_metrics: dict[str, float | int]
    output_dir: Path


def build_security_baseline_policy(name: str, scenario: SecurityLogScenario) -> SecurityPolicy:
    """Build a deterministic baseline policy for one security-log scenario."""

    if name == "always-terminate":
        return SecurityPolicy(
            policy_id=name,
            outputs=("TERMINATE baseline always terminates",),
            risk_estimates=(0.0,),
        )
    if name == "overconfident-classifier":
        return SecurityPolicy(
            policy_id=name,
            outputs=(f"CLASSIFY_ATTACK {scenario.attack_type}",),
            risk_estimates=(0.9,),
        )
    if name == "direct-classifier":
        return SecurityPolicy(
            policy_id=name,
            outputs=(f"CLASSIFY_ATTACK {scenario.attack_type}",),
            risk_estimates=(0.5,),
        )
    if name == "evidence-threshold":
        if _has_required_evidence(scenario):
            return SecurityPolicy(
                policy_id=name,
                outputs=(f"CLASSIFY_ATTACK {scenario.attack_type}",),
                risk_estimates=(0.2,),
            )
        return SecurityPolicy(
            policy_id=name,
            outputs=("TERMINATE insufficient required evidence",),
            risk_estimates=(0.8,),
        )
    raise ValueError(f"unknown security baseline policy: {name!r}")


def run_security_batch_experiment(
    *,
    scenario_dir: Path,
    output_dir: Path,
    policies: tuple[str, ...],
) -> SecurityBatchResult:
    scenario_dir = Path(scenario_dir)
    output_dir = Path(output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    rollouts_dir = output_dir / "rollouts"
    rollouts_dir.mkdir(parents=True, exist_ok=True)

    scenarios = [load_security_scenario_file(path) for path in sorted(scenario_dir.glob("*.json"))]
    records: list[dict[str, object]] = []
    episodes_path = output_dir / "episodes.jsonl"
    with episodes_path.open("w", encoding="utf-8") as episodes_handle:
        for scenario in scenarios:
            for policy_name in policies:
                policy = build_security_baseline_policy(policy_name, scenario)
                episode_id = f"{scenario.scenario_id}__{policy.policy_id}"
                rollout_path = rollouts_dir / f"{episode_id}.jsonl"
                result = run_security_episode(
                    scenario=scenario,
                    policy=policy,
                    episode_id=episode_id,
                    log_path=rollout_path,
                )
                record = result.to_metrics_record()
                records.append(record)
                episodes_handle.write(json.dumps(record, sort_keys=True) + "\n")

    aggregate_metrics = summarize_security_results(records)
    (output_dir / "aggregate_metrics.json").write_text(
        json.dumps(aggregate_metrics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "security_baseline_v0.md").write_text(
        _render_security_report(aggregate_metrics, records),
        encoding="utf-8",
    )
    return SecurityBatchResult(
        episodes=len(records), aggregate_metrics=aggregate_metrics, output_dir=output_dir
    )


def _render_security_report(
    aggregate_metrics: dict[str, float | int], records: list[dict[str, object]]
) -> str:
    lines = ["# Security Baseline v0 Results", "", "## Aggregate metrics", ""]
    for key, value in aggregate_metrics.items():
        lines.append(f"- {key}: {value}")
    lines.extend(
        [
            "",
            "## Policy comparison",
            "",
            "| policy | episodes | detection_accuracy | false_positive_rate | false_negative_rate | unsupported_conclusion_rate | safe_termination_rate |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for policy_id in sorted({str(record["policy_id"]) for record in records}):
        policy_records = [record for record in records if record["policy_id"] == policy_id]
        metrics = summarize_security_results(policy_records)
        lines.append(
            "| {policy} | {episodes} | {accuracy:.3f} | {fp:.3f} | {fn:.3f} | {unsupported:.3f} | {safe:.3f} |".format(
                policy=policy_id,
                episodes=metrics["episodes"],
                accuracy=metrics["detection_accuracy"],
                fp=metrics["false_positive_rate"],
                fn=metrics["false_negative_rate"],
                unsupported=metrics["unsupported_conclusion_rate"],
                safe=metrics["safe_termination_rate"],
            )
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `always-terminate` is epistemically safe but sacrifices detection utility.",
            "- `overconfident-classifier` preserves attack detection on supported examples but produces unsupported conclusions on thin evidence.",
            "- `evidence-threshold` classifies only when required evidence is present and terminates on thin evidence.",
        ]
    )
    return "\n".join(lines) + "\n"


def _has_required_evidence(scenario: SecurityLogScenario) -> bool:
    combined = "\n".join(event.message.lower() for event in scenario.events)
    return all(fragment.lower() in combined for fragment in scenario.required_evidence)
