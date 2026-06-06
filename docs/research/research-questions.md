# Research Questions and Hypotheses

Generated: 2026-06-06

## Primary research question

Can a terminating Markov decision process policy reduce catastrophic tool-use failures in a controlled file-deletion sandbox while preserving acceptable task-completion rates?

## Subquestions

### SQ1: State design

What state representation is sufficient for a file-deletion T-MDP?

Candidate state variables:
- Current task progress.
- Candidate action type: inspect, move, delete, restore, terminate.
- Path class: benign target, protected decoy, trap, unknown.
- Path distance from sandbox root.
- Reversibility: reversible, recoverable, irreversible/simulated irreversible.
- Risk estimate for next action.
- Prior warning count / prior near-miss count.
- Remaining operation budget.

Pass criterion: every state variable must be observable from the sandbox or generated task config; no hidden labels may be used by non-oracle policies.

### SQ2: Termination modeling

Should voluntary termination be represented as:

1. An absorbing terminal state with fixed cost.
2. An action available in every nonterminal state.
3. A policy-level refusal outside the MDP.

Working choice: model it as an explicit action that transitions to an absorbing TASK_TERMINATED state. This keeps termination comparable to continue/delete actions and makes unnecessary termination measurable.

### SQ3: Catastrophe modeling

Should catastrophic failure be represented as:

1. A high-cost absorbing state.
2. A violation flag in logs only.
3. Both.

Working choice: use both. The MDP needs a high-cost absorbing CATASTROPHIC_FAILURE endpoint for policy optimization, while logs need explicit violation labels for evaluation and debugging.

### SQ4: Objective choice

Candidate objectives:
- Minimize expected total cost.
- Minimize expected total cost with catastrophic terminal penalty.
- Constrain catastrophic failure probability below epsilon while maximizing completion.
- Risk-sensitive utility / exponential cost.

Working choice for first implementation: weighted terminal costs plus explicit reporting of catastrophic failure probability. This is easiest to implement and explain. Risk-sensitive variants can be layered after deterministic baselines exist.

### SQ5: Risk estimation

What should supply stepwise risk estimates?

Order:
1. Oracle synthetic risk for sanity checks.
2. Deterministic heuristic risk from sandbox labels and path/action features.
3. Noisy calibrated risk estimator.
4. Optional LLM judge adapter.

Working rule: no LLM judge until deterministic logs and metrics are stable.

## Hypotheses

H1: A no-termination policy has the highest completion rate but nonzero catastrophic failure rate when traps exist.

H2: A simple threshold-termination policy reduces catastrophic failures but over-terminates when risk estimates are noisy.

H3: A T-MDP policy using task progress and risk state achieves a better failure/completion tradeoff than threshold termination.

H4: State design quality will dominate LLM-judge sophistication in the first sandbox.

## Initial experiment metrics

- Task completion rate.
- Voluntary termination rate.
- Catastrophic failure rate.
- Unnecessary termination rate: terminated when a safe completion path existed under oracle labels.
- Average cumulative cost.
- Average steps to terminal state.
- Protected-file survival rate.
- Replay success rate from JSONL logs.
