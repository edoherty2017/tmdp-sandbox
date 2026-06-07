# Test Suite Visual Summary

This note explains the visual test run generated for the T-MDP sandbox project and what the current passing results mean.

## Current result

Command witnessed in the terminal:

```bash
PYTHONPATH=src pytest tests/ -vv --tb=short --color=yes
```

Visual HTML report generated from JUnit XML:

- WSL path: `/mnt/d/ML/tmdp-sandbox/runs/visual-test-report.html`
- Windows path: `D:\ML\tmdp-sandbox\runs\visual-test-report.html`

Latest observed result:

- Total tests: 30
- Passed: 30
- Failed: 0
- Skipped: 0

Interpretation: the current codebase is green. The deterministic safety-evaluation scaffold, baseline policies, episode runner, batch runner, security-log scaffold, and new risk-assessor interface all satisfy the project’s automated expectations.

## What the tests are proving

The repository is a controlled sandbox for studying catastrophic action prevention in terminating decision-process style experiments. The core research question is:

> Can a policy or agent do useful work while avoiding actions that should trigger safe termination?

The tests verify that the project can model that question safely, run repeatable experiments, and measure both utility and safety.

## Test areas

### 1. Batch experiment tests

File: `tests/test_batch_experiment.py`

These tests prove that the batch runner can:

- run multiple scenarios,
- run multiple baseline policies,
- write rollout logs,
- write aggregate metrics,
- produce a markdown policy-comparison report.

Passing result means the project can compare policy behavior across scenarios instead of relying on one-off manual inspection.

### 2. CLI and policy tests

File: `tests/test_cli_and_policies.py`

These tests prove that:

- JSON scenario files load correctly,
- baseline policies emit expected scripted actions,
- the CLI can run a scenario and write rollout/metrics outputs.

The tested baseline policies include:

- `always-terminate`: safest but does no useful work,
- `no-termination`: follows requested actions blindly and may be dangerous,
- `threshold-risk`: continues on low-risk work and terminates before high-risk actions.

Passing result means the project can be exercised from the command line and produces experiment artifacts correctly.

### 3. Episode runner tests

File: `tests/test_episode_runner.py`

An episode is one policy run against one scenario. These tests prove that an episode can:

- build a temporary sandbox file tree,
- apply policy actions step by step,
- log each step,
- stop on termination or completion,
- compute episode-level metrics.

They also verify an important safety distinction:

- attempted catastrophe: a policy tried a dangerous action,
- executed catastrophe: the dangerous action actually happened.

Passing result means the runner can separate blocked/attempted danger from actual catastrophic execution.

### 4. Risk assessor tests

File: `tests/test_risk_assessor.py`

These tests cover the new deterministic risk-assessor interface.

They prove that the risk assessor returns replayable records containing:

- assessor identity,
- action type,
- target path,
- normalized score,
- rationale,
- raw response placeholder,
- failure-mode placeholder.

They also prove that threshold-risk policies can accept an injected assessor and use its scores in requested-action order.

Passing result means risk scoring is now separated from policy behavior. This makes the system ready for later assessor swaps, such as an LLM judge, without rewriting the episode runner or baseline policy framework.

### 5. Risky safety-tradeoff scenario tests

File: `tests/test_risky_safety_tradeoff.py`

These tests prove that the benchmark includes a meaningful tradeoff scenario with both benign work and a protected/trap target.

Expected behavior:

- `no-termination` completes requested work but executes catastrophe,
- `always-terminate` avoids catastrophe but completes no work,
- `threshold-risk` completes safe work, then terminates before the trap.

Passing result means the benchmark is not trivial: it can expose the difference between utility-only behavior, safety-only behavior, and risk-aware termination.

### 6. Sandbox scaffold tests

File: `tests/test_sandbox_scaffold.py`

These are safety-critical infrastructure tests. They prove that the file-deletion sandbox:

- rejects paths that escape the temp root,
- only creates fixture files under the temp root,
- rejects traversal paths such as `../secret`,
- rejects absolute paths,
- parses supported policy actions,
- detects protected-file deletion as catastrophe,
- blocks attempts to escape the sandbox,
- writes JSONL episode logs correctly.

Passing result means the dangerous file-operation simulation is contained and should not delete arbitrary files on the machine.

### 7. Security baseline tests

File: `tests/test_security_baselines.py`

These tests apply the same safety framing to security-log classification.

They compare policies such as:

- `always-terminate`,
- `overconfident-classifier`,
- `direct-classifier`,
- `evidence-threshold`.

The key safety idea is that an agent should not confidently classify an attack unless sufficient required evidence is present.

Passing result means the project can compare security-analysis policies while separating detection utility from unsupported claims.

### 8. Security-log scaffold tests

File: `tests/test_security_log_scaffold.py`

These tests prove that the security-log evaluation scaffold can:

- load normalized security scenarios,
- validate labels and events,
- parse policy outputs,
- score correct attack classifications,
- mark unsupported conclusions,
- treat termination on unknown evidence as safe,
- report detection and safety metrics.

Passing result means the project can evaluate epistemic safety failures, not only physical/file-deletion catastrophes.

## Scientific meaning of the passing suite

The current green suite supports the following claim:

> The T-MDP sandbox has a working deterministic evaluation scaffold for comparing policies that decide whether to continue acting or terminate before potentially catastrophic actions.

The project currently measures both:

- utility: whether useful requested work was completed,
- safety: whether catastrophic or unsupported actions were avoided.

The newest risk-assessor work changes the architecture from hardcoded policy risk values to a more modular pipeline:

```text
Scenario -> Risk Assessor -> Policy Decision -> Episode Runner -> Metrics
```

This makes later experiments cleaner because different risk assessors can be ablated or swapped independently of the rest of the framework.

## Bottom line

The visual test run and generated report show that all 30 current tests pass. There are no detected regressions in the sandbox, runner, CLI, batch metrics, security-log scaffold, or deterministic risk-assessor integration.
