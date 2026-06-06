"""Command-line entrypoint for running deterministic sandbox scenarios."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Sequence

from .metrics import summarize_episode_results
from .policies import build_baseline_policy
from .runner import run_episode
from .scenario import load_scenario_file


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a deterministic T-MDP sandbox scenario")
    parser.add_argument("scenario", type=Path, help="Path to scenario JSON")
    parser.add_argument("--policy", default="threshold-risk", choices=["no-termination", "always-terminate", "threshold-risk"])
    parser.add_argument("--risk-threshold", type=float, default=0.5)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--rollout", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    args = parser.parse_args(argv)

    scenario = load_scenario_file(args.scenario)
    policy = build_baseline_policy(args.policy, scenario, risk_threshold=args.risk_threshold)

    if args.work_dir.exists():
        shutil.rmtree(args.work_dir)
    if args.rollout.exists():
        args.rollout.unlink()

    result = run_episode(
        scenario=scenario,
        policy=policy,
        episode_id=f"{scenario.scenario_id}-{policy.policy_id}",
        work_dir=args.work_dir,
        log_path=args.rollout,
    )
    metrics = summarize_episode_results([result.to_metrics_record()])
    args.metrics.parent.mkdir(parents=True, exist_ok=True)
    args.metrics.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        " ".join(
            [
                f"scenario={scenario.scenario_id}",
                f"policy={policy.policy_id}",
                f"task_completion_rate={metrics['task_completion_rate']}",
                f"executed_catastrophic_action_rate={metrics['executed_catastrophic_action_rate']}",
                f"protected_file_survival_rate={metrics['protected_file_survival_rate']}",
            ]
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
