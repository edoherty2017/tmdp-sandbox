"""Value iteration for finite-state T-MDP models."""

from __future__ import annotations

from .tmdp_model import Action, TMDPModel, TMDPState


def value_iteration(
    model: TMDPModel,
    *,
    tolerance: float = 1e-6,
    max_iterations: int = 10_000,
) -> tuple[dict[TMDPState, float], dict[TMDPState, Action]]:
    """Compute an expected-cost-minimizing deterministic policy."""

    values = {state: 0.0 for state in model.states}
    policy: dict[TMDPState, Action] = {}

    for _ in range(max_iterations):
        delta = 0.0
        next_values = dict(values)
        next_policy: dict[TMDPState, Action] = {}
        for state in model.states:
            actions = model.actions(state)
            if not actions:
                next_values[state] = 0.0
                continue
            best_action = actions[0]
            best_value = _action_value(model, values, state, best_action)
            for action in actions[1:]:
                candidate_value = _action_value(model, values, state, action)
                if candidate_value < best_value:
                    best_action = action
                    best_value = candidate_value
            next_values[state] = best_value
            next_policy[state] = best_action
            delta = max(delta, abs(best_value - values[state]))
        values = next_values
        policy = next_policy
        if delta <= tolerance:
            return values, policy

    raise RuntimeError(f"value iteration did not converge after {max_iterations} iterations")


def greedy_action(policy: dict[TMDPState, Action], state: TMDPState) -> Action:
    """Return the computed greedy action for a nonterminal state."""

    return policy[state]


def _action_value(
    model: TMDPModel,
    values: dict[TMDPState, float],
    state: TMDPState,
    action: Action,
) -> float:
    return sum(
        transition.probability * (transition.cost + values[transition.next_state])
        for transition in model.transitions(state, action)
    )
