"""Security domain batch experiment: T-MDP vs threshold policies with noise sweep.

Generates SecurityScenario instances from labeled OTRF events, runs policies
at five noise levels (sigma=0.00..0.20), and writes aggregate results.

The key comparison:
  T-MDP:        p* = (c_block - c_execute) / c_compromise = (5-1)/10 = 0.4000
  threshold-0.5: fixed block threshold = 0.50

When sigma>0, classifier scores for malicious events (true P≈0.85) can be
noisy-reduced into (0.40, 0.50). T-MDP blocks there; threshold-0.5 does not.
This is the wedge where T-MDP earns its keep over a fixed threshold.

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_security_batch.py

Outputs (written to runs/security_batch/):
    results.json       — per-episode results for all policies × noise levels
    aggregate.json     — per-policy × noise-level aggregate stats
    summary.txt        — human-readable table
"""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier
from tmdp_sandbox.event_spec import SecurityScenario
from tmdp_sandbox.event_spec import EventSpec
from tmdp_sandbox.policies import build_security_tmdp_policy, build_security_threshold_policy
from tmdp_sandbox.preprocessing import load_otrf_labeled_pool
from tmdp_sandbox.security_runner import SecurityScriptedPolicy, run_security_episode

REPO_ROOT = Path(__file__).parent.parent
MALICIOUS_DIR = REPO_ROOT / "data" / "raw" / "malicious"
MODEL_PATH = REPO_ROOT / "models" / "ml_classifier_logistic.joblib"
OUT_DIR = Path(__file__).parent / "security_batch"

N_SCENARIOS = 500
SCENARIO_LENGTH = 20
MALICIOUS_FRACTIONS = [0.0, 0.1, 0.2, 0.3, 0.5]
SEEDS_PER_FRACTION = N_SCENARIOS // len(MALICIOUS_FRACTIONS)

# Costs shared across all policies (evaluator uses COMPROMISE_COST for actual damage)
COMPROMISE_COST = 100.0
BLOCK_COST = 5.0
EXECUTE_STEP_COST = 1.0
DEFER_STEP_COST = 0.5

# T-MDP cost parameters → implicit threshold p* = (5-1)/10 = 0.4000
# Matches the file-deletion experiment cost ratio for direct comparability.
TMDP_COMPROMISE_COST = 10.0   # p* = (BLOCK_COST - EXECUTE_STEP_COST) / TMDP_COMPROMISE_COST = 0.4000

# Noise levels to sweep
SIGMA_VALUES = [0.00, 0.05, 0.10, 0.15, 0.20]


def generate_scenarios(
    benign_pool: list[EventSpec],
    malicious_pool: list[EventSpec],
    rng: random.Random,
    n: int,
    length: int,
    mal_fraction: float,
) -> list[SecurityScenario]:
    n_malicious = max(0, min(length, round(length * mal_fraction)))
    n_benign = length - n_malicious
    scenarios = []
    for i in range(n):
        events = rng.choices(benign_pool, k=n_benign) + (
            rng.choices(malicious_pool, k=n_malicious) if n_malicious > 0 else []
        )
        rng.shuffle(events)
        scenarios.append(SecurityScenario(
            scenario_id=f"sec-f{mal_fraction:.2f}-{i:04d}",
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


def build_always_execute_policy(scenario: SecurityScenario) -> SecurityScriptedPolicy:
    return SecurityScriptedPolicy(
        "always-execute",
        tuple(f"EXECUTE {i}" for i in scenario.requested_executions),
        tuple(0.0 for _ in scenario.requested_executions),
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)

    print("Loading OTRF datasets ...")
    benign_pool, malicious_pool = load_otrf_labeled_pool(MALICIOUS_DIR)
    print(f"  Benign pool:    {len(benign_pool)}")
    print(f"  Malicious pool: {len(malicious_pool)}")

    print(f"\nLoading classifier from {MODEL_PATH} ...")
    classifier = MLCommandClassifier(load_classifier(MODEL_PATH), window_size=10)

    print(f"\nGenerating {N_SCENARIOS} scenarios ...")
    all_scenarios: list[SecurityScenario] = []
    for mal_frac in MALICIOUS_FRACTIONS:
        all_scenarios.extend(generate_scenarios(
            benign_pool, malicious_pool, rng,
            n=SEEDS_PER_FRACTION, length=SCENARIO_LENGTH, mal_fraction=mal_frac,
        ))
    print(f"  Total: {len(all_scenarios)}")

    all_results = []
    t0 = time.time()

    total_runs = len(SIGMA_VALUES) * (4 + 2)  # 4 noise-sensitive policies + 2 static
    print(f"\nRunning {len(all_scenarios)} scenarios × {total_runs} policy-noise combos ...")

    for sigma in SIGMA_VALUES:
        print(f"\n  sigma={sigma:.2f}")
        policies: list[tuple[str, object]] = [
            ("always-execute", build_always_execute_policy),
            ("threshold-0.3", lambda s, sg=sigma: build_security_threshold_policy(
                s, classifier=classifier, block_threshold=0.3, risk_noise_sigma=sg)),
            ("threshold-0.5", lambda s, sg=sigma: build_security_threshold_policy(
                s, classifier=classifier, block_threshold=0.5, risk_noise_sigma=sg)),
            ("threshold-0.7", lambda s, sg=sigma: build_security_threshold_policy(
                s, classifier=classifier, block_threshold=0.7, risk_noise_sigma=sg)),
            ("tmdp-p0.40", lambda s, sg=sigma: build_security_tmdp_policy(
                s, classifier=classifier,
                compromise_cost=TMDP_COMPROMISE_COST,
                block_cost=BLOCK_COST,
                execute_step_cost=EXECUTE_STEP_COST,
                defer_step_cost=DEFER_STEP_COST,
                risk_noise_sigma=sg,
            )),
            ("oracle", build_oracle_policy),
        ]

        for pol_name, pol_builder in policies:
            for scenario in all_scenarios:
                policy = pol_builder(scenario)
                n_true_mal = sum(
                    1 for i in scenario.requested_executions
                    if scenario.events[i].label == "malicious"
                )
                result = run_security_episode(
                    scenario=scenario, policy=policy,
                    episode_id=f"{pol_name}_s{sigma:.2f}_{scenario.scenario_id}",
                    compromise_cost=COMPROMISE_COST,
                    block_cost=BLOCK_COST,
                    execute_step_cost=EXECUTE_STEP_COST,
                    defer_step_cost=DEFER_STEP_COST,
                )
                all_results.append({
                    "policy": pol_name,
                    "sigma": sigma,
                    "scenario_id": scenario.scenario_id,
                    "mal_fraction": float(scenario.scenario_id.split("-")[1][1:]),
                    "n_true_malicious": n_true_mal,
                    "malicious_executed": result.malicious_executed,
                    "blocked_prematurely": result.blocked_prematurely,
                    "all_benign_allowed": result.all_benign_allowed,
                    "deferred_count": result.deferred_count,
                    "cumulative_cost": result.cumulative_cost,
                    "benign_allow_rate": result.benign_allow_rate,
                    "malicious_block_rate": result.malicious_block_rate,
                })
            cnt = sum(1 for r in all_results if r["policy"] == pol_name and r["sigma"] == sigma)
            print(f"    {pol_name}: {cnt} episodes")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    (OUT_DIR / "results.json").write_text(json.dumps(all_results, indent=2))

    agg = _compute_aggregates(all_results)
    (OUT_DIR / "aggregate.json").write_text(json.dumps(agg, indent=2))

    summary = _format_summary(agg)
    (OUT_DIR / "summary.txt").write_text(summary)
    print(f"\n{summary}")

    mcnemar = _compute_mcnemar(all_results)
    (OUT_DIR / "mcnemar.json").write_text(json.dumps(mcnemar, indent=2))
    print("McNemar (tmdp-p0.40 vs threshold-0.5) by sigma:")
    for row in mcnemar:
        print(f"  sigma={row['sigma']:.2f}  discordant={row['discordant']}  "
              f"mal_exec_rate tmdp={row['mal_exec_tmdp']:.3f} vs thresh={row['mal_exec_thresh']:.3f}")


def _compute_aggregates(results: list[dict]) -> dict:
    from collections import defaultdict
    out = {}
    for sigma in SIGMA_VALUES:
        out[str(sigma)] = {}
        for pol in {r["policy"] for r in results}:
            rows = [r for r in results if r["policy"] == pol and r["sigma"] == sigma]
            if not rows:
                continue
            out[str(sigma)][pol] = {
                "n": len(rows),
                "malicious_executed_rate": sum(1 for r in rows if r["malicious_executed"]) / len(rows),
                "blocked_prematurely_rate": sum(1 for r in rows if r["blocked_prematurely"]) / len(rows),
                "mean_benign_allow_rate": sum(r["benign_allow_rate"] for r in rows) / len(rows),
                "mean_malicious_block_rate": sum(r["malicious_block_rate"] for r in rows) / len(rows),
                "mean_cost": sum(r["cumulative_cost"] for r in rows) / len(rows),
            }
    return out


def _compute_mcnemar(results: list[dict]) -> list[dict]:
    """Paired McNemar test: tmdp-p0.40 vs threshold-0.5 on malicious_executed outcome."""
    import math
    rows = []
    for sigma in SIGMA_VALUES:
        tmdp_by_scenario = {
            r["scenario_id"]: r["malicious_executed"]
            for r in results if r["policy"] == "tmdp-p0.40" and r["sigma"] == sigma
        }
        thresh_by_scenario = {
            r["scenario_id"]: r["malicious_executed"]
            for r in results if r["policy"] == "threshold-0.5" and r["sigma"] == sigma
        }
        shared = set(tmdp_by_scenario) & set(thresh_by_scenario)
        # b = tmdp protects but thresh doesn't; c = thresh protects but tmdp doesn't
        b = sum(1 for sid in shared if not tmdp_by_scenario[sid] and thresh_by_scenario[sid])
        c = sum(1 for sid in shared if tmdp_by_scenario[sid] and not thresh_by_scenario[sid])
        discordant = b + c
        # McNemar chi-square (continuity corrected)
        if discordant > 0:
            chi2 = (abs(b - c) - 1) ** 2 / discordant if discordant > 1 else 0.0
            # approximate p from chi2 with 1 df
            p_approx = math.exp(-chi2 / 2) if chi2 > 0 else 1.0
        else:
            chi2, p_approx = 0.0, 1.0
        mal_exec_tmdp = sum(1 for sid in shared if tmdp_by_scenario[sid]) / max(1, len(shared))
        mal_exec_thresh = sum(1 for sid in shared if thresh_by_scenario[sid]) / max(1, len(shared))
        rows.append({
            "sigma": sigma,
            "n_shared": len(shared),
            "b_tmdp_better": b,
            "c_thresh_better": c,
            "discordant": discordant,
            "chi2_cc": chi2,
            "p_approx": p_approx,
            "mal_exec_tmdp": mal_exec_tmdp,
            "mal_exec_thresh": mal_exec_thresh,
        })
    return rows


def _format_summary(agg: dict) -> str:
    pol_order = ["always-execute", "threshold-0.3", "threshold-0.5", "threshold-0.7", "tmdp-p0.40", "oracle"]
    lines = [
        "Security Batch Experiment — T-MDP (p*=0.40) vs Threshold Policies",
        f"Noise sweep: sigma ∈ {SIGMA_VALUES}",
        "=" * 80,
    ]
    for sigma_str, pol_data in sorted(agg.items(), key=lambda x: float(x[0])):
        lines.append(f"\nsigma={float(sigma_str):.2f}")
        lines.append(f"  {'Policy':<22} {'Mal.Exec':>9} {'Ben.Allow':>10} {'Mal.Block':>10} {'AvgCost':>9}")
        lines.append(f"  {'-'*65}")
        for pol in pol_order:
            if pol not in pol_data:
                continue
            d = pol_data[pol]
            lines.append(
                f"  {pol:<22} {d['malicious_executed_rate']:>9.3f}"
                f" {d['mean_benign_allow_rate']:>10.3f}"
                f" {d['mean_malicious_block_rate']:>10.3f}"
                f" {d['mean_cost']:>9.2f}"
            )
    lines.append(f"\nT-MDP implicit threshold: ({BLOCK_COST} - {EXECUTE_STEP_COST}) / {TMDP_COMPROMISE_COST} = {(BLOCK_COST - EXECUTE_STEP_COST) / TMDP_COMPROMISE_COST:.4f}")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
