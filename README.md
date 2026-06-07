# T-MDP Sandbox for Catastrophic Action Prevention

Private research/code workspace for the CS5100 project "Terminating Markov decision processes for catastrophic action prevention."

## Core idea

Model an AI agent's option to self-terminate risky actions as a terminating Markov decision process (T-MDP) with two absorbing endpoints:

- TASK COMPLETED: the agent completes the intended task.
- TASK TERMINATED: the agent stops before executing a risky/catastrophic action.

The first concrete testbed is a controlled file-deletion sandbox where an agent must complete benign file operations while avoiding irreversible or catastrophic deletion behavior.

## Immediate anchors

- Canonical anchor plan: `docs/anchors.md`
- Panel remediation plan: `docs/plans/2026-06-06-panel-remediation-plan.md`
- Honest pre-proposal status: `docs/preproposal-status.md`
- Research prep notes: `docs/research/research-prep.md`
- Source proposal extraction: `docs/source/SandBox_Project_extracted.md`
- Original uploaded proposal: `docs/source/SandBox Project.docx`

## Current status

This repository now contains a finite-state belief T-MDP model with value iteration, observable-feature risk scoring, a T-MDP policy adapter wired into batch experiments, positive termination opportunity cost, and termination-quality metrics. The current example-scenario results are still small smoke-test results, not statistical evidence for the central hypothesis.

The next implementation milestone is scale-out: seed-driven scenario generation, noisy-risk sweeps, confidence intervals, and larger policy comparisons over dozens of generated scenarios.

## Working rules

1. Sandbox safety before agent capability.
2. Reproducible logs before policy comparison.
3. Baseline behavior before risk-sensitive termination.
4. Small, auditable experiments before scale-out.
5. Private repo by default; do not publish datasets, logs, or prompts without review.
