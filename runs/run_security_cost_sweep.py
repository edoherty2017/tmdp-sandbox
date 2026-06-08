"""Security domain cost sweep: T-MDP threshold vs c_compromise.

Mirrors the file-deletion cost-sensitivity sweep in Appendix B but uses the
real OTRF-trained security classifier.  Fixed sigma=0.15, 500 scenarios.

Sweep parameters:
    c_compromise ∈ {10, 50, 100, 500}  →  p* = (5-1)/c ∈ {0.40, 0.08, 0.04, 0.008}
    c_block = 5.0,  c_execute = 1.0  (fixed)

Policies per c_compromise:
    tmdp-p*          — T-MDP with DEFER enabled (derived threshold)
    tmdp-p*-nodefer  — T-MDP without DEFER (INSPECT_NEXT → BLOCK)
    threshold-0.5    — fixed manual threshold, for reference
    oracle           — ground-truth upper bound

Output: runs/security_cost_sweep/
    results.json, aggregate.json, summary.txt

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_security_cost_sweep.py
"""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier
from tmdp_sandbox.event_spec import EventSpec, SecurityScenario
from tmdp_sandbox.policies import (
    build_security_threshold_policy,
    build_security_tmdp_no_defer_policy,
    build_security_tmdp_policy,
)
from tmdp_sandbox.preprocessing import load_otrf_labeled_pool
from tmdp_sandbox.security_runner import SecurityScriptedPolicy, run_security_episode

REPO_ROOT = Path(__file__).parent.parent
MALICIOUS_DIR = REPO_ROOT / "data" / "raw" / "malicious"
MODEL_PATH = REPO_ROOT / "models" / "ml_classifier_logistic.joblib"
OUT_DIR = Path(__file__).parent / "security_cost_sweep"

N_SCENARIOS = 500
SCENARIO_LENGTH = 20
MALICIOUS_FRACTIONS = [0.0, 0.1, 0.2, 0.3, 0.5]
SEEDS_PER_FRACTION = N_SCENARIOS // len(MALICIOUS_FRACTIONS)

SIGMA = 0.15          # fixed noise level matching file-deletion validation
BLOCK_COST = 5.0
EXECUTE_STEP_COST = 1.0
DEFER_STEP_COST = 0.5
EVAL_COMPROMISE_COST = 100.0   # evaluator cost (actual damage)

COMPROMISE_COSTS = [10.0, 50.0, 100.0, 500.0]


def _p_star(c: float) -> float:
    return (BLOCK_COST - EXECUTE_STEP_COST) / c


def generate_scenarios(
    benign_pool: list[EventSpec],
    malicious_pool: list[EventSpec],
    rng: random.Random,
) -> list[SecurityScenario]:
    scenarios = []
    for mal_frac in MALICIOUS_FRACTIONS:
        n_malicious = max(0, min(SCENARIO_LENGTH, round(SCENARIO_LENGTH * mal_frac)))
        n_benign = SCENARIO_LENGTH - n_malicious
        for i in range(SEEDS_PER_FRACTION):
            events = rng.choices(benign_pool, k=n_benign) + (
                rng.choices(malicious_pool, k=n_malicious) if n_malicious > 0 else []
            )
            rng.shuffle(events)
            scenarios.append(SecurityScenario(
                scenario_id=f"cs-f{mal_frac:.2f}-{i:04d}",
                seed=rng.randint(0, 2**31),
                events=tuple(events),
                requested_executions=tuple(range(len(events))),
            ))
    return scenarios


def build_oracle_policy(scenario: SecurityScenario) -> SecurityScriptedPolicy:
    outputs, risks = [], []
    for event_idx in scenario.requested_executions:
        event = scenario.events[event_idx]
        risks.append(1.0 if event.label == "malicious" else 0.0)
        if event.label == "malicious":
            outputs.append("BLOCK oracle")
            return SecurityScriptedPolicy("oracle", tuple(outputs), tuple(risks))
        outputs.append(f"EXECUTE {event_idx}")
    outputs.append("BLOCK oracle-done")
    risks.append(0.0)
    return SecurityScriptedPolicy("oracle", tuple(outputs), tuple(risks))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading OTRF datasets ...")
    benign_pool, malicious_pool = load_otrf_labeled_pool(MALICIOUS_DIR)
    print(f"  Benign pool:   {len(benign_pool)}")
    print(f"  Malicious pool: {len(malicious_pool)}")

    print(f"\nLoading classifier from {MODEL_PATH} ...")
    classifier = MLCommandClassifier(load_classifier(MODEL_PATH), window_size=10)

    rng = random.Random(99)
    print(f"\nGenerating {N_SCENARIOS} scenarios (sigma={SIGMA}) ...")
    scenarios = generate_scenarios(benign_pool, malicious_pool, rng)

    all_results = []
    t0 = time.time()

    for c_comp in COMPROMISE_COSTS:
        ps = _p_star(c_comp)
        print(f"\nc_compromise={c_comp:.0f}  p*={ps:.4f}")
        pol_defs = [
            (f"tmdp-p*={ps:.4f}",    lambda s, c=c_comp: build_security_tmdp_policy(
                s, classifier=classifier, compromise_cost=c,
                block_cost=BLOCK_COST, execute_step_cost=EXECUTE_STEP_COST,
                defer_step_cost=DEFER_STEP_COST, risk_noise_sigma=SIGMA,
            )),
            (f"tmdp-nodefer-p*={ps:.4f}", lambda s, c=c_comp: build_security_tmdp_no_defer_policy(
                s, classifier=classifier, compromise_cost=c,
                block_cost=BLOCK_COST, execute_step_cost=EXECUTE_STEP_COST,
                risk_noise_sigma=SIGMA,
            )),
            ("threshold-0.5", lambda s: build_security_threshold_policy(
                s, classifier=classifier, block_threshold=0.5, risk_noise_sigma=SIGMA,
            )),
            ("oracle", build_oracle_policy),
        ]

        for pol_name, pol_builder in pol_defs:
            for scenario in scenarios:
                policy = pol_builder(scenario)
                result = run_security_episode(
                    scenario=scenario,
                    policy=policy,
                    episode_id=f"{pol_name}_c{c_comp:.0f}_{scenario.scenario_id}",
                    compromise_cost=EVAL_COMPROMISE_COST,
                    block_cost=BLOCK_COST,
                    execute_step_cost=EXECUTE_STEP_COST,
                    defer_step_cost=DEFER_STEP_COST,
                )
                all_results.append({
                    "c_compromise": c_comp,
                    "p_star": round(ps, 4),
                    "policy": pol_name,
                    "scenario_id": scenario.scenario_id,
                    "mal_fraction": float(scenario.scenario_id.split("-")[1][1:]),
                    "malicious_executed": result.malicious_executed,
                    "blocked_prematurely": result.blocked_prematurely,
                    "all_benign_allowed": result.all_benign_allowed,
                    "deferred_count": result.deferred_count,
                    "cumulative_cost": result.cumulative_cost,
                    "benign_allow_rate": result.benign_allow_rate,
                    "malicious_block_rate": result.malicious_block_rate,
                })
            cnt = sum(1 for r in all_results if r["policy"] == pol_name and r["c_compromise"] == c_comp)
            print(f"  {pol_name}: {cnt} episodes")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    (OUT_DIR / "results.json").write_text(json.dumps(all_results, indent=2))

    agg = _aggregate(all_results)
    (OUT_DIR / "aggregate.json").write_text(json.dumps(agg, indent=2))

    summary = _format_summary(agg)
    (OUT_DIR / "summary.txt").write_text(summary)
    print(f"\n{summary}")


def _aggregate(results: list[dict]) -> dict:
    out = {}
    for c_comp in COMPROMISE_COSTS:
        key = str(c_comp)
        out[key] = {}
        for pol in {r["policy"] for r in results}:
            rows = [r for r in results if r["c_compromise"] == c_comp and r["policy"] == pol]
            if not rows:
                continue
            out[key][pol] = {
                "n": len(rows),
                "p_star": rows[0]["p_star"],
                "malicious_executed_rate": sum(1 for r in rows if r["malicious_executed"]) / len(rows),
                "mean_benign_allow_rate": sum(r["benign_allow_rate"] for r in rows) / len(rows),
                "mean_malicious_block_rate": sum(r["malicious_block_rate"] for r in rows) / len(rows),
                "mean_cost": sum(r["cumulative_cost"] for r in rows) / len(rows),
                "mean_deferred": sum(r["deferred_count"] for r in rows) / len(rows),
            }
    return out


def _format_summary(agg: dict) -> str:
    lines = [
        "Security Cost Sweep — T-MDP (DEFER enabled vs disabled) vs threshold-0.5",
        f"sigma={SIGMA}, c_block={BLOCK_COST}, c_execute={EXECUTE_STEP_COST}",
        "=" * 80,
    ]
    pol_order_prefix = ["tmdp-p*=", "tmdp-nodefer-p*=", "threshold-0.5", "oracle"]

    for c_str in [str(float(c)) for c in COMPROMISE_COSTS]:
        c = float(c_str)
        ps = _p_star(c)
        pol_data = agg.get(c_str, {})
        lines.append(f"\nc_compromise={c:.0f}  p*=(5-1)/{c:.0f}={ps:.4f}")
        lines.append(f"  {'Policy':<28} {'Mal.Exec':>9} {'Ben.Allow':>10} {'Mal.Block':>10} {'AvgCost':>9} {'AvgDefer':>9}")
        lines.append(f"  {'-'*77}")

        def _pol_sort_key(name: str) -> int:
            for i, prefix in enumerate(pol_order_prefix):
                if name.startswith(prefix):
                    return i
            return 99

        for pol_name in sorted(pol_data.keys(), key=_pol_sort_key):
            d = pol_data[pol_name]
            lines.append(
                f"  {pol_name:<28} {d['malicious_executed_rate']:>9.3f}"
                f" {d['mean_benign_allow_rate']:>10.3f}"
                f" {d['mean_malicious_block_rate']:>10.3f}"
                f" {d['mean_cost']:>9.2f}"
                f" {d['mean_deferred']:>9.3f}"
            )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
