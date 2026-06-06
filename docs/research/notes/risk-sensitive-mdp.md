# Reading Note Stub: Risk-Sensitive MDP Criteria

Citation target: Bäuerle, Nicole, and Anna Jaśkiewicz. "Markov decision processes with risk-sensitive criteria: an overview." Mathematical Methods of Operations Research 99 (2024): 141-178.

Status: source not yet downloaded/extracted. This note captures what we need from it.

## Why it matters

Expected total cost may hide rare catastrophic deletions. The project needs a defensible risk-sensitive objective or, at minimum, a reason why the first implementation uses weighted terminal costs plus explicit catastrophic-failure reporting.

## Criteria to compare

- Expected total cost with high terminal catastrophe penalty.
- Constrained failure probability: minimize cost subject to `P(catastrophe) <= epsilon`.
- Exponential utility / risk-sensitive expected utility.
- CVaR-like tail-risk objective if feasible.

## Immediate design choice

First implementation should use weighted terminal costs plus explicit reporting of catastrophe probability. This is simple, explainable, and compatible with value iteration on toy state spaces. Risk-sensitive variants should be second-layer experiments once the deterministic sandbox is stable.

## What to extract next

- Which risk-sensitive criterion is easiest to justify for finite-state absorbing MDPs.
- How to phrase limitations of expected-cost optimization.
- Whether constrained-failure-probability framing is standard enough for a CS5100 project.
