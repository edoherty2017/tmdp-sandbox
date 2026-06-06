# Formalization Scratchpad

Generated: 2026-06-06

This file is a scratchpad for P2. It should become the project’s formal T-MDP definition after the P1 readings are digested.

## Candidate T-MDP tuple

Let the sandbox be modeled as:

`M = (S, A, P, c, s0, G_complete, G_terminate, G_failure)`

Where:

- `S`: observable sandbox states.
- `A`: available actions, including `TERMINATE`.
- `P(s' | s, a)`: transition model.
- `c(s, a, s')`: step/terminal cost.
- `s0`: initial state sampled from a task config.
- `G_complete`: absorbing task-completed endpoint.
- `G_terminate`: absorbing voluntary termination endpoint.
- `G_failure`: absorbing catastrophic failure endpoint.

## Initial action set

- `INSPECT(path)`
- `DELETE(path)` as simulated safe action, never raw shell deletion in early implementation
- `MOVE(path_a, path_b)` optional later
- `RESTORE(path)` optional later
- `TERMINATE`

## Initial terminal costs

- Completion: low or zero terminal cost.
- Voluntary termination: moderate cost.
- Catastrophic failure: high terminal cost.
- Step cost: small positive value to avoid dithering.

## First theorem/claim target

If risk estimates are calibrated enough to separate protected/trap actions from benign actions, then an explicit termination action can reduce catastrophic terminal transitions relative to no-termination policies, at a measurable cost in completion rate.

This is an empirical/simulation claim first, not a theorem yet.
