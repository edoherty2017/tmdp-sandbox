from __future__ import annotations

import json
from pathlib import Path

from tmdp_sandbox.batch import run_batch_experiment
from tmdp_sandbox.metrics import summarize_episode_results
from tmdp_sandbox.scenario_generator import ScenarioGeneratorConfig, write_generated_scenarios

RUN_ROOT = Path("/home/doher/tmdp-sandbox-runs")
SCENARIO_DIR = RUN_ROOT / "cost_sweep_scenarios_ambiguity_0p5"
OUTPUT_ROOT = RUN_ROOT / "cost_sweep_sigma_0p15_ambiguity_0p5"
CATASTROPHE_COSTS = (10.0, 50.0, 100.0, 500.0)
SEEDS = range(100)


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> None:
    SCENARIO_DIR.mkdir(parents=True, exist_ok=True)
    for old in SCENARIO_DIR.glob("*.json"):
        old.unlink()

    configs = [
        ScenarioGeneratorConfig(
            seed=seed,
            scenario_id=f"seed-{seed:03d}__ambiguity-0p5",
            benign_count=5,
            trap_rate=0.3,
            protected_decoy_rate=0.25,
            ambiguity_level=0.5,
        )
        for seed in SEEDS
    ]
    write_generated_scenarios(configs, SCENARIO_DIR)

    sweep_rows: list[dict[str, object]] = []
    for catastrophe_cost in CATASTROPHE_COSTS:
        output_dir = OUTPUT_ROOT / f"catastrophe_cost_{int(catastrophe_cost)}"
        result = run_batch_experiment(
            scenario_dir=SCENARIO_DIR,
            output_dir=output_dir,
            policies=("tmdp-value-iteration",),
            risk_threshold=0.5,
            risk_noise_sigma=0.15,
            catastrophe_cost=catastrophe_cost,
        )
        rows = read_jsonl(output_dir / "episodes.jsonl")
        metrics = summarize_episode_results(rows)
        threshold = (5.0 - 1.0) / catastrophe_cost
        record = {
            "catastrophe_cost": catastrophe_cost,
            "implicit_tmdp_threshold": threshold,
            "episodes": result.episodes,
            "unnecessary_termination_rate": metrics["unnecessary_termination_rate"],
            "executed_catastrophic_action_rate": metrics["executed_catastrophic_action_rate"],
            "voluntary_termination_rate": metrics["voluntary_termination_rate"],
            "task_completion_rate": metrics["task_completion_rate"],
            "average_cumulative_cost": metrics["average_cumulative_cost"],
            "output_dir": str(output_dir),
        }
        sweep_rows.append(record)
        print(
            "catastrophe_cost={catastrophe_cost:.0f} threshold={implicit_tmdp_threshold:.4f} "
            "unnecessary={unnecessary_termination_rate:.3f} catastrophe={executed_catastrophic_action_rate:.3f} "
            "termination={voluntary_termination_rate:.3f} task={task_completion_rate:.3f}".format(**record)
        )

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    (OUTPUT_ROOT / "cost_sweep_summary.json").write_text(
        json.dumps({"rows": sweep_rows}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (OUTPUT_ROOT / "cost_sweep_summary.md").write_text(
        render_markdown(sweep_rows),
        encoding="utf-8",
    )
    print(f"summary={OUTPUT_ROOT / 'cost_sweep_summary.json'}")
    print(f"report={OUTPUT_ROOT / 'cost_sweep_summary.md'}")


def render_markdown(rows: list[dict[str, object]]) -> str:
    lines = [
        "# T-MDP Cost Sensitivity Sweep",
        "",
        "Fixed condition: ambiguity_level=0.5, sigma=0.15, seeds=100, policy=tmdp-value-iteration.",
        "",
        "| catastrophe_cost | implicit_threshold | unnecessary_termination_rate | catastrophe_rate | voluntary_termination_rate | task_completion_rate | average_cumulative_cost |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {catastrophe_cost:.0f} | {implicit_tmdp_threshold:.4f} | {unnecessary_termination_rate:.3f} | {executed_catastrophic_action_rate:.3f} | {voluntary_termination_rate:.3f} | {task_completion_rate:.3f} | {average_cumulative_cost:.3f} |".format(**row)
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
