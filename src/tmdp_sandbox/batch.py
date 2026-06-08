"""Batch experiment runner for baseline policy comparisons."""

from __future__ import annotations

import json
import math
import shutil
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from .metrics import summarize_episode_results
from .policies import build_baseline_policy, build_tmdp_value_iteration_policy
from .risk import ObservableFeatureRiskAssessor
from .risk_noise import apply_noise
from .runner import run_episode
from .scenario import SandboxScenario, load_scenario_file
from .tmdp_model import RiskBin


@dataclass(frozen=True)
class BatchExperimentResult:
    episodes: int
    aggregate_metrics: dict[str, float | int]
    output_dir: Path


def run_batch_experiment(
    *,
    scenario_dir: Path,
    output_dir: Path,
    policies: tuple[str, ...],
    risk_threshold: float = 0.5,
    risk_noise_sigma: float = 0.0,
    inspection_delta: float = 0.2,
    catastrophe_cost: float = 100.0,
    write_rollouts: bool = True,
) -> BatchExperimentResult:
    """Run all JSON scenarios across selected baseline policies.

    Set write_rollouts=False to skip per-episode JSONL files. Use this for
    large batches (10k+ episodes) where writing thousands of small files is
    the bottleneck. Summary JSON and aggregate episodes.jsonl are always written.
    """

    scenario_dir = Path(scenario_dir)
    output_dir = Path(output_dir)
    work_root = output_dir / "work"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    work_root.mkdir(parents=True, exist_ok=True)

    rollouts_dir: Path | None = None
    if write_rollouts:
        rollouts_dir = output_dir / "rollouts"
        rollouts_dir.mkdir(parents=True, exist_ok=True)

    episode_records: list[dict[str, object]] = []
    scenario_paths = sorted(scenario_dir.glob("*.json"))
    for scenario_path in scenario_paths:
        scenario = load_scenario_file(scenario_path)
        for policy_name in policies:
            policy = _build_policy(
                policy_name,
                scenario,
                risk_threshold=risk_threshold,
                risk_noise_sigma=risk_noise_sigma,
                inspection_delta=inspection_delta,
                catastrophe_cost=catastrophe_cost,
            )
            episode_id = f"{scenario.scenario_id}__{policy.policy_id}"
            log_path = (rollouts_dir / f"{episode_id}.jsonl") if rollouts_dir is not None else None
            result = run_episode(
                scenario=scenario,
                policy=policy,
                episode_id=episode_id,
                work_dir=work_root / episode_id,
                log_path=log_path,
                catastrophe_cost=catastrophe_cost,
            )
            episode_records.append(result.to_metrics_record())

    aggregate_metrics = summarize_episode_results(episode_records)
    _write_json(output_dir / "aggregate_metrics.json", aggregate_metrics)
    _write_jsonl(output_dir / "episodes.jsonl", episode_records)
    (output_dir / "baseline_v0.md").write_text(
        _render_report(episode_records, aggregate_metrics), encoding="utf-8"
    )
    return BatchExperimentResult(
        episodes=len(episode_records),
        aggregate_metrics=aggregate_metrics,
        output_dir=output_dir,
    )


def _build_policy(
    policy_name: str,
    scenario: SandboxScenario,
    *,
    risk_threshold: float,
    risk_noise_sigma: float,
    inspection_delta: float,
    catastrophe_cost: float,
):
    if policy_name == "tmdp-value-iteration":
        assessor = ObservableFeatureRiskAssessor()
        base_score_by_path = {
            path: assessor.assess_delete(scenario=scenario, path=path).score
            for path in scenario.requested_deletions
        }
        p_catastrophic_by_path = {
            path: apply_noise(
                base_score=base_score,
                seed=scenario.seed + index,
                sigma=risk_noise_sigma,
            )
            for index, (path, base_score) in enumerate(base_score_by_path.items())
        }
        observable_risk_by_path: dict[str, RiskBin] = {
            path: _risk_bin(score)
            for path, score in base_score_by_path.items()
        }
        return build_tmdp_value_iteration_policy(
            scenario,
            observable_risk_by_path=observable_risk_by_path,
            p_catastrophic_by_path=p_catastrophic_by_path,
            inspection_observations_by_path=None,
            catastrophe_cost=catastrophe_cost,
        )
    if policy_name == "observable-threshold-risk":
        return build_baseline_policy(
            policy_name,
            scenario,
            risk_threshold=risk_threshold,
            risk_assessor=_NoisyObservableRiskAssessor(
                scenario_seed=scenario.seed,
                sigma=risk_noise_sigma,
            ),
        )
    return build_baseline_policy(policy_name, scenario, risk_threshold=risk_threshold)


class _NoisyObservableRiskAssessor:
    assessor_id = "observable-feature-noisy-v0"

    def __init__(self, *, scenario_seed: int, sigma: float) -> None:
        self._base = ObservableFeatureRiskAssessor()
        self._scenario_seed = scenario_seed
        self._sigma = sigma

    def assess_delete(self, *, scenario: SandboxScenario, path: str):
        assessment = self._base.assess_delete(scenario=scenario, path=path)
        try:
            index = scenario.requested_deletions.index(path)
        except ValueError:
            index = 0
        noisy_score = apply_noise(
            base_score=assessment.score,
            seed=self._scenario_seed + index,
            sigma=self._sigma,
        )
        return replace(
            assessment,
            assessor_id=self.assessor_id,
            score=noisy_score,
            rationale=(
                f"observable path features produced base score {assessment.score:.3f}; "
                f"seeded Gaussian noise with sigma={self._sigma:.3f} produced {noisy_score:.3f}"
            ),
        )


def _risk_bin(score: float) -> RiskBin:
    if score < 1.0 / 3.0:
        return "low"
    if score < 2.0 / 3.0:
        return "medium"
    return "high"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _wilson_interval(rows: list[dict[str, object]], key: str, z: float = 1.96) -> tuple[float, float]:
    n = len(rows)
    if n == 0:
        return (0.0, 0.0)
    successes = sum(1 for row in rows if bool(row[key]))
    p_hat = successes / n
    denom = 1.0 + z * z / n
    center = (p_hat + z * z / (2.0 * n)) / denom
    margin = z * math.sqrt((p_hat * (1.0 - p_hat) + z * z / (4.0 * n)) / n) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def _normal_mean_interval(rows: list[dict[str, object]], key: str, z: float = 1.96) -> tuple[float, float]:
    values = [cast(float, row[key]) for row in rows]
    if not values:
        return (0.0, 0.0)
    mean = sum(values) / len(values)
    if len(values) == 1:
        return (mean, mean)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    margin = z * math.sqrt(variance / len(values))
    return (mean - margin, mean + margin)


def _format_interval(interval: tuple[float, float]) -> str:
    return f"[{interval[0]:.3f}, {interval[1]:.3f}]"


def _render_report(
    episode_records: list[dict[str, object]], aggregate_metrics: dict[str, float | int]
) -> str:
    lines = [
        "# Baseline v0 Results",
        "",
        "## Aggregate metrics",
        "",
    ]
    for key, value in aggregate_metrics.items():
        lines.append(f"- {key}: {value}")
    lines.extend(
        [
            "",
            "## Policy comparison",
            "",
            "| policy | episodes | task_completion_rate | task_completion_rate_ci95 | voluntary_termination_rate | voluntary_termination_rate_ci95 | appropriate_termination_rate | appropriate_termination_rate_ci95 | unnecessary_termination_rate | unnecessary_termination_rate_ci95 | average_cumulative_cost | average_cumulative_cost_ci95 | executed_catastrophic_action_rate | executed_catastrophic_action_rate_ci95 | protected_file_survival_rate | protected_file_survival_rate_ci95 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for policy_id in sorted({str(row["policy_id"]) for row in episode_records}):
        rows = [row for row in episode_records if row["policy_id"] == policy_id]
        metrics = summarize_episode_results(rows)
        lines.append(
            "| {policy} | {episodes} | {task:.3f} | {task_ci} | {term:.3f} | {term_ci} | {appropriate:.3f} | {appropriate_ci} | {unnecessary:.3f} | {unnecessary_ci} | {cost:.3f} | {cost_ci} | {cat:.3f} | {cat_ci} | {survival:.3f} | {survival_ci} |".format(
                policy=policy_id,
                episodes=metrics["episodes"],
                task=float(metrics["task_completion_rate"]),
                task_ci=_format_interval(_wilson_interval(rows, "task_completed")),
                term=float(metrics["voluntary_termination_rate"]),
                term_ci=_format_interval(_wilson_interval(rows, "voluntarily_terminated")),
                appropriate=float(metrics["appropriate_termination_rate"]),
                appropriate_ci=_format_interval(_wilson_interval(rows, "appropriate_termination")),
                unnecessary=float(metrics["unnecessary_termination_rate"]),
                unnecessary_ci=_format_interval(_wilson_interval(rows, "unnecessary_termination")),
                cost=float(metrics["average_cumulative_cost"]),
                cost_ci=_format_interval(_normal_mean_interval(rows, "cumulative_cost")),
                cat=float(metrics["executed_catastrophic_action_rate"]),
                cat_ci=_format_interval(_wilson_interval(rows, "executed_catastrophe")),
                survival=float(metrics["protected_file_survival_rate"]),
                survival_ci=_format_interval(_normal_mean_interval(rows, "protected_file_survival_rate")),
            )
        )
    lines.append("")
    return "\n".join(lines)
