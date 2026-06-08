"""Sequential block architecture evaluation.

Compares two episode-termination strategies for the T-MDP security policy:

  stop-on-first  (original): block entire episode on first BLOCK decision
  sequential     (new):      BLOCK_EVENT per suspicious event, episode continues

The key claim: sequential block improves benign_allow_rate with no loss in safety
because benign events that happen to follow a malicious event still execute.

Usage:
    cd /mnt/d/ML/tmdp-sandbox
    python runs/run_sequential_eval.py

Outputs (runs/sequential_eval/):
    summary.txt     — human-readable comparison table
    results.json    — per-episode data
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.classifier import MLCommandClassifier, load_classifier
from tmdp_sandbox.event_spec import EventSpec, SecurityScenario
from tmdp_sandbox.policies import (
    build_security_sequential_policy,
    build_security_threshold_policy,
    build_security_tmdp_policy,
)
from tmdp_sandbox.preprocessing import load_otrf_labeled_pool
from tmdp_sandbox.security_runner import SecurityScriptedPolicy, run_security_episode

REPO_ROOT = Path(__file__).parent.parent
MALICIOUS_DIR = REPO_ROOT / "data" / "raw" / "malicious"
MODEL_PATH = REPO_ROOT / "models" / "ml_classifier_logistic.joblib"
OUT_DIR = Path(__file__).parent / "sequential_eval"

N_SCENARIOS = 500
SCENARIO_LENGTH = 20
MALICIOUS_FRACTIONS = [0.1, 0.2, 0.3]
SEEDS_PER_FRACTION = N_SCENARIOS // len(MALICIOUS_FRACTIONS)

COMPROMISE_COST = 100.0
BLOCK_COST = 5.0
EXECUTE_STEP_COST = 1.0
DEFER_STEP_COST = 0.5
TMDP_COMPROMISE_COST = 10.0   # p* = (5-1)/10 = 0.40
SIGMA = 0.15


def _generate_scenarios(
    benign_pool: list[EventSpec],
    malicious_pool: list[EventSpec],
    rng: random.Random,
    n: int,
    length: int,
    mal_fraction: float,
) -> list[SecurityScenario]:
    n_malicious = max(1, round(length * mal_fraction))
    n_benign = length - n_malicious
    scenarios = []
    for i in range(n):
        events = rng.choices(benign_pool, k=n_benign) + rng.choices(malicious_pool, k=n_malicious)
        rng.shuffle(events)
        scenarios.append(SecurityScenario(
            scenario_id=f"seq-f{mal_fraction:.2f}-{i:04d}",
            seed=rng.randint(0, 2**31),
            events=tuple(events),
            requested_executions=tuple(range(length)),
        ))
    return scenarios


def _oracle_stop_on_first(scenario: SecurityScenario) -> SecurityScriptedPolicy:
    outputs, risks = [], []
    for event_idx in scenario.requested_executions:
        event = scenario.events[event_idx]
        risks.append(1.0 if event.label == "malicious" else 0.0)
        if event.label == "malicious":
            outputs.append("BLOCK oracle-stop")
            return SecurityScriptedPolicy("oracle-stop", tuple(outputs), tuple(risks))
        outputs.append(f"EXECUTE {event_idx}")
    outputs.append("BLOCK oracle-done")
    risks.append(0.0)
    return SecurityScriptedPolicy("oracle-stop", tuple(outputs), tuple(risks))


def _oracle_sequential(scenario: SecurityScenario) -> SecurityScriptedPolicy:
    outputs, risks = [], []
    for event_idx in scenario.requested_executions:
        event = scenario.events[event_idx]
        risks.append(1.0 if event.label == "malicious" else 0.0)
        if event.label == "malicious":
            outputs.append(f"BLOCK_EVENT {event_idx}")
        else:
            outputs.append(f"EXECUTE {event_idx}")
    return SecurityScriptedPolicy("oracle-sequential", tuple(outputs), tuple(risks))


def _aggregate(results: list[dict]) -> dict:
    if not results:
        return {}
    n = len(results)
    return {
        "n": n,
        "mal_exec_rate": sum(r["malicious_executed"] for r in results) / n,
        "ben_allow_rate": sum(r["benign_allow_rate"] for r in results) / n,
        "mal_block_rate": sum(r["malicious_block_rate"] for r in results) / n,
        "avg_cost": sum(r["cumulative_cost"] for r in results) / n,
        "avg_defer": sum(r["deferred_count"] for r in results) / n,
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)

    print("Loading OTRF datasets ...")
    benign_pool, malicious_pool = load_otrf_labeled_pool(MALICIOUS_DIR)
    print(f"  Benign pool: {len(benign_pool)}  Malicious pool: {len(malicious_pool)}")

    print(f"Loading classifier from {MODEL_PATH} ...")
    raw_pipeline = load_classifier(MODEL_PATH)
    classifier = MLCommandClassifier(raw_pipeline, window_size=10)

    all_scenarios: list[SecurityScenario] = []
    for frac in MALICIOUS_FRACTIONS:
        n = N_SCENARIOS // len(MALICIOUS_FRACTIONS)
        all_scenarios.extend(_generate_scenarios(benign_pool, malicious_pool, rng, n, SCENARIO_LENGTH, frac))

    print(f"Generated {len(all_scenarios)} scenarios across {MALICIOUS_FRACTIONS} malicious fractions")

    policies = {
        "tmdp-stop-on-first": lambda sc: build_security_tmdp_policy(
            sc, classifier=classifier,
            compromise_cost=TMDP_COMPROMISE_COST,
            block_cost=BLOCK_COST,
            execute_step_cost=EXECUTE_STEP_COST,
            defer_step_cost=DEFER_STEP_COST,
            risk_noise_sigma=SIGMA,
        ),
        "tmdp-sequential": lambda sc: build_security_sequential_policy(
            sc, classifier=classifier,
            compromise_cost=TMDP_COMPROMISE_COST,
            block_cost=BLOCK_COST,
            execute_step_cost=EXECUTE_STEP_COST,
            defer_step_cost=DEFER_STEP_COST,
            risk_noise_sigma=SIGMA,
        ),
        "threshold-0.5": lambda sc: build_security_threshold_policy(
            sc, classifier=classifier, block_threshold=0.5, risk_noise_sigma=SIGMA,
        ),
        "oracle-stop": _oracle_stop_on_first,
        "oracle-sequential": _oracle_sequential,
    }

    all_results: list[dict] = []
    by_policy: dict[str, list[dict]] = {p: [] for p in policies}

    print(f"\nRunning {len(all_scenarios)} scenarios × {len(policies)} policies ...")
    for sc_idx, scenario in enumerate(all_scenarios):
        if sc_idx % 100 == 0:
            print(f"  scenario {sc_idx}/{len(all_scenarios)}")
        for pol_name, pol_fn in policies.items():
            policy = pol_fn(scenario)
            result = run_security_episode(
                scenario=scenario,
                policy=policy,
                episode_id=f"{scenario.scenario_id}-{pol_name}",
                compromise_cost=COMPROMISE_COST,
                block_cost=BLOCK_COST,
                execute_step_cost=EXECUTE_STEP_COST,
                defer_step_cost=DEFER_STEP_COST,
            )
            record = result.to_metrics_record()
            record["policy_id_override"] = pol_name
            all_results.append(record)
            by_policy[pol_name].append(record)

    agg = {pol: _aggregate(recs) for pol, recs in by_policy.items()}
    (OUT_DIR / "results.json").write_text(json.dumps(all_results, indent=2))
    (OUT_DIR / "aggregate.json").write_text(json.dumps(agg, indent=2))

    # ── Wilcoxon signed-rank test: stop-on-first vs sequential benign_allow_rate ──
    from scipy.stats import wilcoxon
    stop_bars = [r["benign_allow_rate"] for r in by_policy["tmdp-stop-on-first"]]
    seq_bars  = [r["benign_allow_rate"] for r in by_policy["tmdp-sequential"]]
    # Paired by scenario (same order, same index)
    try:
        w_stat, w_p = wilcoxon(seq_bars, stop_bars, alternative="greater")
        wilcoxon_str = f"Wilcoxon signed-rank (sequential > stop-on-first): W={w_stat:.1f}, p={w_p:.3e}"
    except Exception as exc:
        wilcoxon_str = f"Wilcoxon test skipped: {exc}"

    pol_order = ["tmdp-stop-on-first", "tmdp-sequential", "threshold-0.5",
                 "oracle-stop", "oracle-sequential"]

    lines = [
        "Sequential Block Architecture Evaluation",
        f"sigma={SIGMA}, c_compromise={TMDP_COMPROMISE_COST} (p*=0.40), c_block={BLOCK_COST}, "
        f"c_execute={EXECUTE_STEP_COST}",
        f"N={len(all_scenarios)} scenarios (malicious fractions: {MALICIOUS_FRACTIONS})",
        "=" * 80,
        "",
        f"  {'Policy':<26} {'MalExec':>8} {'BenAllow':>9} {'MalBlock':>9} {'AvgCost':>9} {'Defer':>6}",
        f"  {'-'*68}",
    ]
    for pol in pol_order:
        a = agg.get(pol, {})
        lines.append(
            f"  {pol:<26} {a.get('mal_exec_rate',0):.3f}    {a.get('ben_allow_rate',0):.3f}     "
            f"{a.get('mal_block_rate',0):.3f}    {a.get('avg_cost',0):7.2f}  {a.get('avg_defer',0):.3f}"
        )

    lines += [
        "",
        "Key: stop-on-first = blocks entire episode; sequential = BLOCK_EVENT per event, continues.",
        "",
        "Sequential improvement in benign_allow_rate:",
    ]
    stop_bar = agg.get("tmdp-stop-on-first", {}).get("ben_allow_rate", 0)
    seq_bar = agg.get("tmdp-sequential", {}).get("ben_allow_rate", 0)
    delta = seq_bar - stop_bar
    lines.append(
        f"  tmdp-sequential:    {seq_bar:.4f}"
        f"  vs  tmdp-stop-on-first: {stop_bar:.4f}  (delta = {delta:+.4f})"
    )
    oracle_stop = agg.get("oracle-stop", {}).get("ben_allow_rate", 0)
    oracle_seq = agg.get("oracle-sequential", {}).get("ben_allow_rate", 0)
    lines.append(
        f"  oracle-sequential:  {oracle_seq:.4f}"
        f"  vs  oracle-stop-on-first: {oracle_stop:.4f}  (theoretical max improvement)"
    )
    lines.append("")
    lines.append(wilcoxon_str)

    summary = "\n".join(lines)
    print(f"\n{summary}")
    (OUT_DIR / "summary.txt").write_text(summary)
    print(f"\nResults → {OUT_DIR}/")


if __name__ == "__main__":
    main()
