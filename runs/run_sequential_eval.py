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
    results.json    — library versions, sign tests, per-episode data
"""

from __future__ import annotations

import json
import math
import platform
import random
import sys
from importlib import metadata
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
from tmdp_sandbox.risk_noise import apply_noise
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

RESAMPLING_NOTE = (
    "Scenarios are resampled with replacement from fixed benign/malicious event pools, "
    "so paired scenarios are not independent draws from a wider population."
)


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


def _threshold_sequential(
    scenario: SecurityScenario,
    *,
    classifier: MLCommandClassifier,
    block_threshold: float = 0.5,
    risk_noise_sigma: float = 0.0,
) -> SecurityScriptedPolicy:
    """Threshold baseline with sequential semantics.

    Same scoring as build_security_threshold_policy, but emits BLOCK_EVENT
    (block this event, continue) instead of the episode-terminating BLOCK —
    the same swap that distinguishes tmdp-sequential from tmdp-stop-on-first.
    """
    outputs: list[str] = []
    risks: list[float] = []
    for step, event_idx in enumerate(scenario.requested_executions):
        event = scenario.events[event_idx]
        p_malicious = classifier.score_event(
            event, scenario.events, decision_index=event_idx
        )
        if risk_noise_sigma > 0.0:
            p_malicious = apply_noise(
                base_score=p_malicious,
                seed=scenario.seed + step,
                sigma=risk_noise_sigma,
            )
        risks.append(p_malicious)
        if p_malicious > block_threshold:
            outputs.append(f"BLOCK_EVENT {event_idx}")
        else:
            outputs.append(f"EXECUTE {event_idx}")
    return SecurityScriptedPolicy("threshold-sequential", tuple(outputs), tuple(risks))


def _aggregate(results: list[dict]) -> dict:
    if not results:
        return {}
    n = len(results)
    total_cost = sum(r["cumulative_cost"] for r in results)
    total_decisions = sum(r["steps"] for r in results)
    return {
        "n": n,
        "mal_exec_rate": sum(r["malicious_executed"] for r in results) / n,
        "ben_allow_rate": sum(r["benign_allow_rate"] for r in results) / n,
        "mal_block_rate": sum(r["malicious_block_rate"] for r in results) / n,
        "avg_cost": total_cost / n,
        "avg_cost_per_decision": total_cost / total_decisions if total_decisions else 0.0,
        "avg_defer": sum(r["deferred_count"] for r in results) / n,
    }


def _exact_sign_test(diffs: list[float]) -> dict:
    """Exact one-sided sign test on paired differences (zeros dropped).

    Returns positive/zero/negative counts plus P(#positive >= observed | p=0.5),
    computed exactly via math.comb — no normal approximation.
    """
    n_pos = sum(1 for d in diffs if d > 0)
    n_neg = sum(1 for d in diffs if d < 0)
    n_zero = len(diffs) - n_pos - n_neg
    n = n_pos + n_neg
    p = sum(math.comb(n, k) for k in range(n_pos, n + 1)) / 2**n if n > 0 else 1.0
    return {
        "n_pairs": len(diffs),
        "n_positive": n_pos,
        "n_zero": n_zero,
        "n_negative": n_neg,
        "p_one_sided_exact": p,
    }


def _library_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for pkg in ("scikit-learn", "numpy", "pandas", "joblib"):
        versions[pkg] = metadata.version(pkg)
    return versions


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
        "threshold-0.5-sequential": lambda sc: _threshold_sequential(
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

    # ── Exact sign test: stop-on-first vs sequential benign_allow_rate ──
    # Replaces the earlier Wilcoxon normal approximation; the improvement is
    # structural (stop-on-first forfeits every event after its first block),
    # so the honest statistic is the exact paired count.
    def _paired_diffs(seq_pol: str, stop_pol: str) -> list[float]:
        # Paired by scenario (same order, same index)
        return [
            s["benign_allow_rate"] - t["benign_allow_rate"]
            for s, t in zip(by_policy[seq_pol], by_policy[stop_pol])
        ]

    sign_tests = {
        "tmdp-sequential_vs_tmdp-stop-on-first": _exact_sign_test(
            _paired_diffs("tmdp-sequential", "tmdp-stop-on-first")
        ),
        "threshold-0.5-sequential_vs_threshold-0.5": _exact_sign_test(
            _paired_diffs("threshold-0.5-sequential", "threshold-0.5")
        ),
    }

    results_payload = {
        "library_versions": _library_versions(),
        "note": RESAMPLING_NOTE,
        "sign_tests": sign_tests,
        "avg_cost_per_decision": {pol: agg[pol]["avg_cost_per_decision"] for pol in agg},
        "episodes": all_results,
    }
    (OUT_DIR / "results.json").write_text(json.dumps(results_payload, indent=2))
    (OUT_DIR / "aggregate.json").write_text(json.dumps(agg, indent=2))

    pol_order = ["tmdp-stop-on-first", "tmdp-sequential", "threshold-0.5",
                 "threshold-0.5-sequential", "oracle-stop", "oracle-sequential"]

    lines = [
        "Sequential Block Architecture Evaluation",
        f"sigma={SIGMA}, c_compromise={TMDP_COMPROMISE_COST} (p*=0.40), c_block={BLOCK_COST}, "
        f"c_execute={EXECUTE_STEP_COST}",
        f"N={len(all_scenarios)} scenarios (malicious fractions: {MALICIOUS_FRACTIONS})",
        "=" * 80,
        "",
        f"  {'Policy':<26} {'MalExec':>8} {'BenAllow':>9} {'MalBlock':>9} {'AvgCost':>9} {'Cost/Dec':>9} {'Defer':>6}",
        f"  {'-'*78}",
    ]
    for pol in pol_order:
        a = agg.get(pol, {})
        lines.append(
            f"  {pol:<26} {a.get('mal_exec_rate',0):.3f}    {a.get('ben_allow_rate',0):.3f}     "
            f"{a.get('mal_block_rate',0):.3f}    {a.get('avg_cost',0):7.2f}  "
            f"{a.get('avg_cost_per_decision',0):8.3f}  {a.get('avg_defer',0):.3f}"
        )

    lines += [
        "",
        "Key: stop-on-first = blocks entire episode; sequential = BLOCK_EVENT per event, continues.",
        "Cost/Dec = total cost / total decision steps (episode cost is not comparable across",
        "architectures that process different amounts of work).",
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
    thr_stop_bar = agg.get("threshold-0.5", {}).get("ben_allow_rate", 0)
    thr_seq_bar = agg.get("threshold-0.5-sequential", {}).get("ben_allow_rate", 0)
    lines.append(
        f"  threshold-0.5-seq:  {thr_seq_bar:.4f}"
        f"  vs  threshold-0.5-stop: {thr_stop_bar:.4f}  (delta = {thr_seq_bar - thr_stop_bar:+.4f})"
    )
    oracle_stop = agg.get("oracle-stop", {}).get("ben_allow_rate", 0)
    oracle_seq = agg.get("oracle-sequential", {}).get("ben_allow_rate", 0)
    lines.append(
        f"  oracle-sequential:  {oracle_seq:.4f}"
        f"  vs  oracle-stop-on-first: {oracle_stop:.4f}  (theoretical max improvement)"
    )
    lines.append(
        "  The threshold-0.5-sequential arm shows the architectural gain is"
        " decision-layer-agnostic."
    )
    lines.append("")
    lines.append("Exact sign test (sequential > stop-on-first, paired per-scenario benign_allow_rate):")
    for label, key in [
        ("tmdp", "tmdp-sequential_vs_tmdp-stop-on-first"),
        ("threshold", "threshold-0.5-sequential_vs_threshold-0.5"),
    ]:
        st = sign_tests[key]
        lines.append(
            f"  {label:<10} +{st['n_positive']} / 0:{st['n_zero']} / -{st['n_negative']}"
            f"  (n={st['n_pairs']} pairs)  exact one-sided p={st['p_one_sided_exact']:.3e}"
        )
    lines.append(
        "  The gain is structural — stop-on-first forfeits every event after its first"
        " block — so the test is descriptive, not inferential."
    )
    lines.append("")
    lines.append(f"Note: {RESAMPLING_NOTE}")

    summary = "\n".join(lines)
    print(f"\n{summary}")
    (OUT_DIR / "summary.txt").write_text(summary)
    print(f"\nResults → {OUT_DIR}/")


if __name__ == "__main__":
    main()
