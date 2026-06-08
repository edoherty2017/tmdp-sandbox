# Test Suite Summary

Last updated: 2026-06-07

## Current result

```bash
python3 -m pytest -q
# 110 passed in 3.38s
```

All 110 tests passing. No failures, no skips.

## Test areas

### T-MDP core (domain-agnostic)

- `test_tmdp_value_iteration.py` — value iteration convergence, threshold formula `p* = (c_block-c_execute)/c_compromise`, boundary transitions
- `test_risk_noise.py` — seeded noise model, clamped scores, determinism
- `test_scenario_generator.py` — seed reproducibility, trap/decoy/benign ratios

### Security pipeline (Phases 1–3)

- `test_context_window.py` — baseline integrity check, suspicious process detection, obfuscation patterns, sliding-window feature aggregation
- `test_classifier.py` — MLCommandClassifier training, calibrated probability output, feature extraction
- `test_security_runner.py` — SecurityScriptedPolicy, run_security_episode, EXECUTE/BLOCK outcomes, cost accumulation
- `test_end_to_end_pipeline.py` — full Phase 1→2→3 pipeline with synthetic trained classifier; 7 scenarios

### File-deletion sandbox (legacy regression)

- `test_batch_experiment.py` — batch runner, policy comparison table, JSONL logs
- `test_episode_runner.py` — temp-root guard, step logging, catastrophe vs attempted-catastrophe distinction
- `test_sandbox_scaffold.py` — path traversal rejection, protected-file detection, absolute-path blocking
- `test_cli_and_policies.py` — JSON scenario loading, scripted policy outputs, CLI entry point

### Security-log layer (offline classifier, separate from real-time pipeline)

- `test_security_baselines.py` — always-terminate / overconfident / direct-classifier / evidence-threshold policies
- `test_security_log_scaffold.py` — scenario loading, label validation, detection metrics, epistemic safety

## Scientific meaning

The suite validates the full stack:

1. T-MDP value iteration produces the analytically correct threshold from cost parameters.
2. The Phase 1 feature extractor correctly flags LOLBin processes, obfuscation, and high-risk event IDs.
3. The Phase 2 classifier produces calibrated P(malicious) ∈ [0, 1] and integrates with the T-MDP adapter.
4. The security episode runner correctly tracks EXECUTE/BLOCK outcomes and cumulative cost.
5. The file-deletion sandbox (used for T-MDP validation) remains regression-clean.

Type checking and the test suite verify code correctness, not feature-level correctness. Feature-level validation is in `runs/run_security_batch.py` (15,000-episode noise sweep) and `runs/train_classifier.py` (CV metrics).
