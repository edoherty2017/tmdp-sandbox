# Reading Note Stub: Stochastic Shortest Path Problems

Citation target: Bertsekas, Dimitri P., and John N. Tsitsiklis. "An Analysis of Stochastic Shortest Path Problems." Mathematics of Operations Research 16, no. 3 (1991): 580-595.

Status: source not yet downloaded/extracted. This note captures why it matters and what to extract next.

## Why it matters

The T-MDP sandbox is naturally an undiscounted stochastic shortest path problem: an agent starts in an initial file-task state, pays step costs, and eventually reaches one of several absorbing terminal states: task completion, voluntary termination, or catastrophic failure.

## What to extract next

- Definition of proper and improper policies.
- Conditions for finite expected total cost.
- How terminal/absorbing states are handled.
- Whether all policies must be proper or only at least one proper policy must exist.
- Dynamic programming equations for stochastic shortest path.

## Immediate design implications

- Add small positive step cost to avoid infinite dithering.
- Ensure `TERMINATE` is always available so at least one proper policy exists.
- Treat catastrophic failure as absorbing with high terminal cost.
- Evaluation should report if a policy fails to terminate within horizon.
