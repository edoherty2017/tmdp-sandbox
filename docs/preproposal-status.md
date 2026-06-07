# Pre-Proposal Status: T-MDP Sandbox for Catastrophic Action Prevention

## Honest current status

This project now has the first real algorithmic milestone implemented: a finite-state belief T-MDP with value iteration and an explicit `TERMINATE` action.

Completed so far:

- Literature map connecting the project to the Off-Switch Game, TerMDPs, stochastic shortest path MDPs, risk-sensitive objectives, and ToolEmu-style sandboxing.
- A controlled file-deletion sandbox with validated fixture paths.
- JSONL step logging for replayable episodes.
- Scripted baseline policies for no-termination, always-termination, and threshold-risk behavior.
- Belief-state T-MDP model with stochastic DELETE transitions over `p_catastrophic`.
- INSPECT transitions that update posterior catastrophe belief and enforce belief consistency.
- Expected-cost value iteration.
- Observable-feature risk assessor that does not read hidden labels.
- T-MDP value-iteration policy wired into batch experiments.
- Appropriate/unnecessary termination metrics and positive termination opportunity cost.

Not completed yet:

- Seed-driven scenario generator for dozens of scenarios.
- Noisy-risk sweeps driven by scenario seeds.
- Confidence intervals / variance reporting across seeds.
- Large-scale statistical comparison over generated scenarios.

## What the current results mean

The current example-scenario batch table is now a valid smoke test of the full measurement harness, including the T-MDP policy. It should still not be treated as statistical evidence for the central hypothesis because it uses only three hand-written scenarios.

Oracle-label risk remains available only as an explicitly named sanity-check assessor. Non-oracle T-MDP runs should use observable-feature risk or later seeded noisy-risk estimates.

## Current experiment plan

The first scaled experiment should compare:

1. No-termination baseline.
2. Always-terminate baseline.
3. Threshold-risk baseline using observable/noisy risk.
4. Oracle label-risk sanity-check upper bound.
5. T-MDP value-iteration policy.

The comparison should report:

- `task_completion_rate`
- `voluntary_termination_rate`
- `appropriate_termination_rate`
- `unnecessary_termination_rate`
- `attempted_catastrophic_action_rate`
- `executed_catastrophic_action_rate`
- `protected_file_survival_rate`
- `average_cumulative_cost`
- `average_steps_to_terminal_state`
- Confidence intervals or variance across seeds

## Updated pre-proposal wording

At this stage, the project has completed the literature-mapping, sandbox infrastructure, and first algorithmic implementation milestones. The repository now includes a finite-state belief T-MDP with value iteration, observable-feature risk estimates, positive termination cost, and termination-quality metrics wired into the batch experiment harness. Current results over three hand-written scenarios remain smoke-test evidence only. The next milestone is a seeded scenario generator and noisy-risk experiment comparing T-MDP value iteration against no-termination, always-termination, threshold-risk, and oracle sanity-check baselines across enough scenarios to report variance or confidence intervals.
