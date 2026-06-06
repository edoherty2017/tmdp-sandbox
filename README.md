# T-MDP Sandbox for Catastrophic Action Prevention

Private research/code workspace for the CS5100 project "Terminating Markov decision processes for catastrophic action prevention."

## Core idea

Model an AI agent's option to self-terminate risky actions as a terminating Markov decision process (T-MDP) with two absorbing endpoints:

- TASK COMPLETED: the agent completes the intended task.
- TASK TERMINATED: the agent stops before executing a risky/catastrophic action.

The first concrete testbed is a controlled file-deletion sandbox where an agent must complete benign file operations while avoiding irreversible or catastrophic deletion behavior.

## Immediate anchors

- Canonical anchor plan: `docs/anchors.md`
- Research prep notes: `docs/research/research-prep.md`
- Source proposal extraction: `docs/source/SandBox_Project_extracted.md`
- Original uploaded proposal: `docs/source/SandBox Project.docx`

## Working rules

1. Sandbox safety before agent capability.
2. Reproducible logs before policy comparison.
3. Baseline behavior before risk-sensitive termination.
4. Small, auditable experiments before scale-out.
5. Private repo by default; do not publish datasets, logs, or prompts without review.
