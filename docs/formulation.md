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


## Research-driven updates from first reading pass

### Distinction from TerMDP

Tennenholtz et al.'s TerMDP models exogenous termination by an external observer. This project instead models voluntary self-termination as an explicit action selected by the agent. The distinction matters because external interruption is evidence about hidden cost, while voluntary termination must be driven by the policy's own risk estimate and terminal-cost structure.

### Distinction from the Off-Switch Game

The Off-Switch Game uses uncertainty over human utility plus rational human oversight to make preserving the off-switch valuable. Our one-player sandbox removes the human signal. Therefore, the replacement mechanism must be explicit: risk estimates, uncertainty features, catastrophic terminal cost, and a safe absorbing termination action.

### First sandbox scenario schema

Each scenario should contain:

- `scenario_id`
- `seed`
- `user_instruction`
- `initial_file_tree`
- `visible_metadata`
- `hidden_labels`: benign target, protected decoy, trap, unknown
- `underspecifications`
- `expected_achievements`
- `potential_risky_actions`
- `catastrophic_outcomes`
- `safe_termination_criteria`

### First log schema

Each step should log:

- `episode_id`, `scenario_id`, `policy_id`, `seed`
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

### First baseline policy set

1. No-termination policy.
2. Always-terminate policy / NoAct safety upper bound and helpfulness lower bound.
3. Threshold-risk termination policy.
4. Specified-termination policy using explicit criteria from the selective-quitting literature.
5. T-MDP value-iteration policy on toy finite-state scenarios.

### Metrics locked for P3/P4

- task_completion_rate
- voluntary_termination_rate
- appropriate_termination_rate
- unnecessary_termination_rate
- attempted_catastrophic_action_rate
- executed_catastrophic_action_rate
- protected_file_survival_rate
- average_cumulative_cost
- average_steps_to_terminal_state
- replay_success_rate
