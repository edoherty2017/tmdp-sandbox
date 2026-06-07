"""Finite-state T-MDP model for the first value-iteration policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

TerminalState = Literal["complete", "terminate", "failure"]
RiskBin = Literal["low", "medium", "high"]
Action = Literal["DELETE_NEXT", "INSPECT_NEXT", "TERMINATE"]

_RISK_BINS: tuple[RiskBin, ...] = ("low", "medium", "high")
_TERMINALS: tuple[TerminalState, ...] = ("complete", "terminate", "failure")


@dataclass(frozen=True)
class TMDPState:
    """Observable finite state plus the agent's current catastrophe belief.

    `p_catastrophic` is a belief derived from observable risk signals. It is not
    a hidden fixture label. DELETE transitions are stochastic under this belief.
    """

    progress: int
    candidate_index: int
    observable_risk_bin: RiskBin
    p_catastrophic: float
    prior_warnings: int
    remaining_budget: int
    terminal: TerminalState | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.p_catastrophic <= 1.0:
            raise ValueError(f"p_catastrophic must be in [0, 1], got {self.p_catastrophic!r}")


@dataclass(frozen=True)
class Transition:
    """One transition branch for P(s' | s, a)."""

    probability: float
    next_state: TMDPState
    cost: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError(f"transition probability must be in [0, 1], got {self.probability!r}")


@dataclass(frozen=True)
class TMDPCosts:
    """Expected-cost parameters for finite-state value iteration."""

    catastrophe: float = 100.0
    termination: float = 5.0
    delete_step: float = 1.0
    inspect_step: float = 0.25
    completion: float = 0.0


class TMDPModel:
    """A small finite-state terminating MDP for one requested deletion target.

    The model is conditioned on the agent's belief about catastrophe risk, not on
    the hidden ground-truth label. INSPECT samples an observable risk result and
    updates the belief to the corresponding posterior probability.
    """

    def __init__(
        self,
        *,
        initial_p_catastrophic: float,
        initial_risk_bin: RiskBin,
        inspection_observations: dict[RiskBin, tuple[float, float]] | None = None,
        costs: TMDPCosts | None = None,
    ) -> None:
        if initial_risk_bin not in _RISK_BINS:
            raise ValueError(f"unknown risk bin: {initial_risk_bin!r}")
        _validate_probability(initial_p_catastrophic, "initial_p_catastrophic")
        self.costs = costs if costs is not None else TMDPCosts()
        self.initial_state = TMDPState(
            progress=0,
            candidate_index=0,
            observable_risk_bin=initial_risk_bin,
            p_catastrophic=initial_p_catastrophic,
            prior_warnings=1 if initial_risk_bin == "high" else 0,
            remaining_budget=1,
            terminal=None,
        )
        self.inspection_observations = _normalize_observations(
            inspection_observations
            if inspection_observations is not None
            else {initial_risk_bin: (1.0, initial_p_catastrophic)}
        )
        _check_belief_consistency(self.inspection_observations, initial_p_catastrophic)
        self.states = self._enumerate_reachable_states()

    @classmethod
    def single_candidate(
        cls,
        *,
        p_catastrophic: float,
        observable_risk_bin: RiskBin,
        inspection_observations: dict[RiskBin, tuple[float, float]] | None = None,
        catastrophe_cost: float = 100.0,
        termination_cost: float = 5.0,
        delete_step_cost: float = 1.0,
        inspect_step_cost: float = 0.25,
        completion_cost: float = 0.0,
    ) -> "TMDPModel":
        """Build the first one-target belief-state model used by milestone-1 tests."""

        return cls(
            initial_p_catastrophic=p_catastrophic,
            initial_risk_bin=observable_risk_bin,
            inspection_observations=inspection_observations,
            costs=TMDPCosts(
                catastrophe=catastrophe_cost,
                termination=termination_cost,
                delete_step=delete_step_cost,
                inspect_step=inspect_step_cost,
                completion=completion_cost,
            ),
        )

    def actions(self, state: TMDPState) -> tuple[Action, ...]:
        if state.terminal is not None:
            return ()
        if state.remaining_budget > 0:
            return ("DELETE_NEXT", "INSPECT_NEXT", "TERMINATE")
        return ("DELETE_NEXT", "TERMINATE")

    def transitions(self, state: TMDPState, action: Action) -> tuple[Transition, ...]:
        if state.terminal is not None:
            return ()
        if action == "TERMINATE":
            return (
                Transition(
                    probability=1.0,
                    next_state=self._terminal_state("terminate", state),
                    cost=self.costs.termination,
                ),
            )
        if action == "DELETE_NEXT":
            failure = Transition(
                probability=state.p_catastrophic,
                next_state=self._terminal_state("failure", state),
                cost=self.costs.delete_step + self.costs.catastrophe,
            )
            complete = Transition(
                probability=1.0 - state.p_catastrophic,
                next_state=self._terminal_state("complete", state),
                cost=self.costs.delete_step + self.costs.completion,
            )
            return tuple(t for t in (failure, complete) if t.probability > 0.0)
        if action == "INSPECT_NEXT":
            if state.remaining_budget <= 0:
                raise ValueError("INSPECT_NEXT is unavailable with no remaining budget")
            return tuple(
                Transition(
                    probability=probability,
                    next_state=TMDPState(
                        progress=state.progress,
                        candidate_index=state.candidate_index,
                        observable_risk_bin=risk_bin,
                        p_catastrophic=posterior,
                        prior_warnings=min(2, state.prior_warnings + (1 if risk_bin == "high" else 0)),
                        remaining_budget=state.remaining_budget - 1,
                        terminal=None,
                    ),
                    cost=self.costs.inspect_step,
                )
                for risk_bin, (probability, posterior) in self.inspection_observations.items()
            )
        raise ValueError(f"unknown action: {action!r}")

    def _terminal_state(self, terminal: TerminalState, source: TMDPState) -> TMDPState:
        return TMDPState(
            progress=1 if terminal == "complete" else 0,
            candidate_index=1 if terminal == "complete" else 0,
            observable_risk_bin=source.observable_risk_bin,
            p_catastrophic=source.p_catastrophic,
            prior_warnings=source.prior_warnings,
            remaining_budget=0,
            terminal=terminal,
        )

    def _enumerate_reachable_states(self) -> tuple[TMDPState, ...]:
        seen: set[TMDPState] = set()
        frontier = [self.initial_state]
        while frontier:
            state = frontier.pop()
            if state in seen:
                continue
            seen.add(state)
            for action in self.actions(state):
                for transition in self.transitions(state, action):
                    if transition.next_state not in seen:
                        frontier.append(transition.next_state)
        for state in list(seen):
            if state.terminal is None:
                for terminal in _TERMINALS:
                    seen.add(self._terminal_state(terminal, state))
        return tuple(sorted(seen, key=repr))


def _check_belief_consistency(
    observations: dict[RiskBin, tuple[float, float]],
    prior: float,
    tolerance: float = 1e-6,
) -> None:
    """Verify that the weighted posteriors equal the prior (law of total probability)."""
    expected_posterior = sum(prob * posterior for prob, posterior in observations.values())
    if abs(expected_posterior - prior) > tolerance:
        raise ValueError(
            f"inspection_observations violate the law of total probability: "
            f"sum(P(obs_i) * posterior_i) = {expected_posterior:.8f}, "
            f"expected prior = {prior:.8f}"
        )


def _normalize_observations(
    observations: dict[RiskBin, tuple[float, float]]
) -> dict[RiskBin, tuple[float, float]]:
    unknown = set(observations) - set(_RISK_BINS)
    if unknown:
        raise ValueError(f"unknown risk bins in inspection observations: {sorted(unknown)!r}")
    total = 0.0
    for risk_bin, (probability, posterior) in observations.items():
        if probability < 0.0:
            raise ValueError(f"observation probability for {risk_bin!r} must be nonnegative")
        _validate_probability(posterior, f"posterior for {risk_bin!r}")
        total += probability
    if total <= 0.0:
        raise ValueError("inspection observation distribution must have positive mass")
    return {
        risk_bin: (probability / total, posterior)
        for risk_bin, (probability, posterior) in observations.items()
        if probability > 0.0
    }


def _validate_probability(value: float, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {value!r}")
