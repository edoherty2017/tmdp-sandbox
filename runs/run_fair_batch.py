from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from tmdp_sandbox.batch import run_batch_experiment
from tmdp_sandbox.metrics import summarize_episode_results
from tmdp_sandbox.scenario_generator import ScenarioGeneratorConfig, write_generated_scenarios

ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT = Path("/home/doher/tmdp-sandbox-runs")
SCENARIO_DIR = RUN_ROOT / "fair_comparison_scenarios"
OUTPUT_ROOT = RUN_ROOT / "fair_comparison_cat10"
POLICIES = (
    "no-termination",
    "always-terminate",
    "threshold-risk",
    "observable-threshold-risk",
    "tmdp-value-iteration",
)
AMBIGUITY_LEVELS = (0.0, 0.5, 1.0)
SIGMAS = (0.0, 0.15)
SEEDS = range(100)


def scenario_id(seed: int, ambiguity: float) -> str:
    return f"seed-{seed:03d}__ambiguity-{ambiguity:.1f}".replace(".", "p")


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

    all_rows: list[dict[str, object]] = []
    for sigma in SIGMAS:
        out = OUTPUT_ROOT / f"sigma_{sigma:.2f}".replace(".", "p")
        result = run_batch_experiment(
            scenario_dir=SCENARIO_DIR,
            output_dir=out,
            policies=POLICIES,
            risk_threshold=0.5,
            risk_noise_sigma=sigma,
            catastrophe_cost=10.0,
        )
        rows = read_jsonl(out / "episodes.jsonl")
        for row in rows:
            row["sigma"] = sigma
            row["catastrophe_cost"] = 10.0
            row["risk_threshold"] = 0.5
        all_rows.extend(rows)
        print(f"sigma={sigma:.2f} episodes={result.episodes} output={out}")

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
            "catastrophe_cost": 10.0,
            "termination_cost": 5.0,
            "delete_step_cost": 1.0,
            "implicit_tmdp_threshold": (5.0 - 1.0) / 10.0,
            "risk_threshold": 0.5,
        },
        "overall": summarize_episode_results(all_rows),
        "by_sigma_policy": group_summary(all_rows, ("sigma", "policy_id")),
        "by_sigma_policy_ambiguity": group_summary(all_rows, ("sigma", "policy_id", "ambiguity_level")),
    }
    (OUTPUT_ROOT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"combined_episodes={len(all_rows)}")
    print(f"summary={OUTPUT_ROOT / 'summary.json'}")
    print(f"episodes={combined_path}")


if __name__ == "__main__":
    main()
