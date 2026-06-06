# Deterministic file-deletion sandbox scaffold

This scaffold is the first executable substrate for the T-MDP catastrophic-action-prevention project.

## Scenario record

Initial JSON-like scenario fields:

- `scenario_id`: stable scenario identifier.
- `seed`: deterministic rollout seed.
- `user_instruction`: instruction shown to the policy.
- `files`: fixture files created under an episode temp root only.
  - `path`: relative POSIX-style path. Absolute paths and `..` traversal are rejected.
  - `label`: one of `benign`, `protected`, or `trap`.
  - `content`: file contents.
- `requested_deletions`: task targets a naive policy will try to delete. This may intentionally include trap paths in risky scenarios so the experiment exposes the safety/usefulness tradeoff.
- `expected_achievements`: task-success conditions.
- `catastrophic_outcomes`: outcomes that count as catastrophic failure.
- `safe_termination_criteria`: conditions under which voluntary `TERMINATE` is appropriate.

## Action language

Initial parser supports:

- `DELETE <relative-path>`
- `TERMINATE <reason>`

All file actions are resolved through the temp-root guard before execution.

## Episode log

The JSONL logger writes one record per step with:

- `episode_id`
- `scenario_id`
- `policy_id`
- `seed`
- `step`
- `state_observation`
- `risk_estimate`
- `raw_policy_output`
- `parsed_action`
- `action_valid`
- `transition`
- `attempted_catastrophe`
- `executed_catastrophe`
- `termination_reason`
- `cumulative_cost`

## Episode runner

The first runner accepts a `SandboxScenario`, a deterministic `ScriptedPolicy`, an episode ID, a work directory, and a JSONL log path. It:

1. Creates the fixture tree under the work directory.
2. Reads scripted policy outputs in order.
3. Parses `DELETE` and `TERMINATE` actions.
4. Applies file actions through the temp-root guard.
5. Logs every step.
6. Returns an `EpisodeResult` with task/safety metrics.

Initial aggregate metrics are computed by `summarize_episode_results`:

- `episodes`
- `task_completion_rate`
- `voluntary_termination_rate`
- `attempted_catastrophic_action_rate`
- `executed_catastrophic_action_rate`
- `protected_file_survival_rate`
- `average_steps_to_terminal_state`

## CLI scenario runs

Example scenario JSON files live under `examples/scenarios/`.

Run a baseline policy with:

```bash
PYTHONPATH=src python3 -m tmdp_sandbox.cli examples/scenarios/basic_cleanup.json \
  --policy threshold-risk \
  --risk-threshold 0.8 \
  --work-dir runs/basic_cleanup/work \
  --rollout runs/basic_cleanup/rollout.jsonl \
  --metrics runs/basic_cleanup/metrics.json
```

Initial built-in policies:

- `no-termination`: blindly follows scenario `requested_deletions` and never voluntarily terminates.
- `always-terminate`: emits `TERMINATE baseline always terminates` immediately.
- `threshold-risk`: follows requested deletions only while their deterministic risk estimate is under the configured threshold, then terminates before a risky target.

## Batch experiments

Run all example scenarios across the initial baselines from Python:

```python
from pathlib import Path
from tmdp_sandbox.batch import run_batch_experiment

run_batch_experiment(
    scenario_dir=Path("examples/scenarios"),
    output_dir=Path("runs/baseline_v0"),
    policies=("no-termination", "always-terminate", "threshold-risk"),
    risk_threshold=0.8,
)
```

The batch runner writes:

- `aggregate_metrics.json`
- `episodes.jsonl`
- one rollout JSONL per scenario/policy under `rollouts/`
- `baseline_v0.md` with a policy comparison table

## Safety invariant

Production sandbox code must never act on files outside the episode temp root. Traversal and absolute paths are rejected before file operations.
