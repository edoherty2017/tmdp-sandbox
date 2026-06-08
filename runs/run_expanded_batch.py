"""Expanded fair-comparison batch: 300 seeds x 5 ambiguity x 5 sigma = 37,500 episodes.

Skips per-episode rollout files (write_rollouts=False) to avoid the WSL
small-file performance bottleneck. Writes aggregate episodes.jsonl and
summary JSON only.

Run from the repo root:
    python3 runs/run_expanded_batch.py

Output: /home/doher/tmdp-sandbox-runs/expanded_batch/
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from tmdp_sandbox.batch import run_batch_experiment
from tmdp_sandbox.metrics import summarize_episode_results
from tmdp_sandbox.scenario_generator import ScenarioGeneratorConfig, write_generated_scenarios

RUN_ROOT = Path("/home/doher/tmdp-sandbox-runs")
SCENARIO_DIR = RUN_ROOT / "expanded_batch_scenarios"
OUTPUT_ROOT = RUN_ROOT / "expanded_batch"

POLICIES = (
    "no-termination",
    "always-terminate",
    "threshold-risk",
    "observable-threshold-risk",
    "tmdp-value-iteration",
)
AMBIGUITY_LEVELS = (0.0, 0.25, 0.5, 0.75, 1.0)
SIGMAS = (0.0, 0.05, 0.10, 0.15, 0.20)
SEEDS = range(300)

TERMINATION_COST = 5.0
DELETE_STEP_COST = 1.0
CATASTROPHE_COST = 10.0
IMPLICIT_THRESHOLD = (TERMINATION_COST - DELETE_STEP_COST) / CATASTROPHE_COST  # 0.4000


def scenario_id(seed: int, ambiguity: float) -> str:
    return f"seed-{seed:03d}__ambiguity-{ambiguity:.2f}".replace(".", "p")


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def infer_ambiguity(row: dict[str, object]) -> float:
    sid = str(row["scenario_id"])
    token = sid.rsplit("ambiguity-", 1)[1]
    return float(token.replace("p", "."))


def group_summary(rows: list[dict[str, object]], keys: tuple[str, ...]) -> list[dict[str, object]]:
    groups: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        augmented = dict(row)
        augmented["ambiguity_level"] = infer_ambiguity(row)
        groups[tuple(augmented[key] for key in keys)].append(augmented)

    output: list[dict[str, object]] = []
    for key_values, group_rows in sorted(groups.items(), key=lambda item: item[0]):
        record = {key: value for key, value in zip(keys, key_values)}
        record.update(summarize_episode_results(group_rows))
        output.append(record)
    return output


def main() -> None:
    total_scenarios = len(SEEDS) * len(AMBIGUITY_LEVELS)
    total_episodes = total_scenarios * len(SIGMAS) * len(POLICIES)
    print(f"Generating {total_scenarios} scenarios ({len(SEEDS)} seeds x {len(AMBIGUITY_LEVELS)} ambiguity levels)")
    print(f"Running {total_episodes} episodes ({len(SIGMAS)} sigma x {len(POLICIES)} policies), rollouts disabled")
    print(f"Implicit T-MDP threshold: {IMPLICIT_THRESHOLD:.4f}")

    SCENARIO_DIR.mkdir(parents=True, exist_ok=True)
    for old in SCENARIO_DIR.glob("*.json"):
        old.unlink()

    configs = [
        ScenarioGeneratorConfig(
            seed=seed,
            scenario_id=scenario_id(seed, ambiguity),
            benign_count=5,
            trap_rate=0.3,
            protected_decoy_rate=0.25,
            ambiguity_level=ambiguity,
        )
        for ambiguity in AMBIGUITY_LEVELS
        for seed in SEEDS
    ]
    paths = write_generated_scenarios(configs, SCENARIO_DIR)
    print(f"Wrote {len(paths)} scenario files to {SCENARIO_DIR}")

    all_rows: list[dict[str, object]] = []
    for sigma in SIGMAS:
        out = OUTPUT_ROOT / f"sigma_{sigma:.2f}".replace(".", "p")
        result = run_batch_experiment(
            scenario_dir=SCENARIO_DIR,
            output_dir=out,
            policies=POLICIES,
            risk_threshold=0.5,
            risk_noise_sigma=sigma,
            catastrophe_cost=CATASTROPHE_COST,
            write_rollouts=False,
        )
        rows = read_jsonl(out / "episodes.jsonl")
        for row in rows:
            row["sigma"] = sigma
            row["catastrophe_cost"] = CATASTROPHE_COST
            row["risk_threshold"] = 0.5
        all_rows.extend(rows)
        print(f"sigma={sigma:.2f}  episodes={result.episodes}  output={out}")

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    combined_path = OUTPUT_ROOT / "episodes_all.jsonl"
    combined_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in all_rows),
        encoding="utf-8",
    )

    summary = {
        "design": {
            "scenarios": len(paths),
            "seeds": len(list(SEEDS)),
            "ambiguity_levels": list(AMBIGUITY_LEVELS),
            "sigmas": list(SIGMAS),
            "policies": list(POLICIES),
            "benign_count": 5,
            "trap_rate": 0.3,
            "protected_decoy_rate": 0.25,
            "catastrophe_cost": CATASTROPHE_COST,
            "termination_cost": TERMINATION_COST,
            "delete_step_cost": DELETE_STEP_COST,
            "implicit_tmdp_threshold": IMPLICIT_THRESHOLD,
            "scripted_risk_threshold": 0.5,
            "total_episodes": len(all_rows),
        },
        "overall": summarize_episode_results(all_rows),
        "by_sigma_policy": group_summary(all_rows, ("sigma", "policy_id")),
        "by_sigma_policy_ambiguity": group_summary(all_rows, ("sigma", "policy_id", "ambiguity_level")),
        "by_ambiguity_policy": group_summary(all_rows, ("ambiguity_level", "policy_id")),
    }
    summary_path = OUTPUT_ROOT / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"\nDone. {len(all_rows)} total episodes.")
    print(f"summary={summary_path}")
    print(f"episodes={combined_path}")


if __name__ == "__main__":
    main()
