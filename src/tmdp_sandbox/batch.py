"""Batch experiment runner for baseline policy comparisons."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .metrics import summarize_episode_results
from .policies import build_baseline_policy
from .runner import run_episode
from .scenario import load_scenario_file


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
) -> BatchExperimentResult:
    """Run all JSON scenarios across selected baseline policies."""

    scenario_dir = Path(scenario_dir)
    output_dir = Path(output_dir)
    rollouts_dir = output_dir / "rollouts"
    work_root = output_dir / "work"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    rollouts_dir.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)

    episode_records: list[dict[str, object]] = []
    scenario_paths = sorted(scenario_dir.glob("*.json"))
    for scenario_path in scenario_paths:
        scenario = load_scenario_file(scenario_path)
        for policy_name in policies:
            policy = build_baseline_policy(policy_name, scenario, risk_threshold=risk_threshold)
            episode_id = f"{scenario.scenario_id}__{policy.policy_id}"
            result = run_episode(
                scenario=scenario,
                policy=policy,
                episode_id=episode_id,
                work_dir=work_root / episode_id,
                log_path=rollouts_dir / f"{episode_id}.jsonl",
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


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


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
            "| policy | episodes | task_completion_rate | voluntary_termination_rate | executed_catastrophic_action_rate | protected_file_survival_rate |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for policy_id in sorted({str(row["policy_id"]) for row in episode_records}):
        rows = [row for row in episode_records if row["policy_id"] == policy_id]
        metrics = summarize_episode_results(rows)
        lines.append(
            "| {policy} | {episodes} | {task:.3f} | {term:.3f} | {cat:.3f} | {survival:.3f} |".format(
                policy=policy_id,
                episodes=metrics["episodes"],
                task=float(metrics["task_completion_rate"]),
                term=float(metrics["voluntary_termination_rate"]),
                cat=float(metrics["executed_catastrophic_action_rate"]),
                survival=float(metrics["protected_file_survival_rate"]),
            )
        )
    lines.append("")
    return "\n".join(lines)
