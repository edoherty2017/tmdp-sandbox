import pytest

from tmdp_sandbox.tmdp_model import TMDPModel, TMDPState
from tmdp_sandbox.value_iteration import greedy_action, value_iteration


def test_value_iteration_chooses_terminate_when_catastrophe_belief_makes_delete_expensive():
    model = TMDPModel.single_candidate(
        p_catastrophic=1.0,
        observable_risk_bin="high",
        catastrophe_cost=1000.0,
        termination_cost=5.0,
        delete_step_cost=1.0,
        completion_cost=0.0,
    )

    values, policy = value_iteration(model, tolerance=1e-9)

    assert greedy_action(policy, model.initial_state) == "TERMINATE"
    assert values[model.initial_state] == 5.0


def test_value_iteration_chooses_delete_when_catastrophe_belief_is_low():
    model = TMDPModel.single_candidate(
        p_catastrophic=0.0,
        observable_risk_bin="low",
        catastrophe_cost=1000.0,
        termination_cost=5.0,
        delete_step_cost=1.0,
        completion_cost=0.0,
    )

    values, policy = value_iteration(model, tolerance=1e-9)

    assert greedy_action(policy, model.initial_state) == "DELETE_NEXT"
    assert values[model.initial_state] == 1.0


def test_delete_transition_uses_catastrophe_belief_instead_of_hidden_label():
    model = TMDPModel.single_candidate(
        p_catastrophic=0.25,
        observable_risk_bin="medium",
        catastrophe_cost=1000.0,
        termination_cost=5.0,
        delete_step_cost=1.0,
        completion_cost=0.0,
    )

    transitions = model.transitions(model.initial_state, "DELETE_NEXT")

    assert [(t.probability, t.next_state.terminal, t.cost) for t in transitions] == [
        (0.25, "failure", 1001.0),
        (0.75, "complete", 1.0),
    ]


def test_inspect_can_be_optimal_when_observation_changes_belief_enough():
    # Posteriors are calibrated: 0.9 * 0.0 + 0.1 * 0.1 = 0.01 == prior.
    model = TMDPModel.single_candidate(
        p_catastrophic=0.01,
        observable_risk_bin="medium",
        inspection_observations={
            "low": (0.9, 0.0),
            "high": (0.1, 0.1),
        },
        catastrophe_cost=1000.0,
        termination_cost=5.0,
        delete_step_cost=1.0,
        inspect_step_cost=0.25,
        completion_cost=0.0,
    )

    values, policy = value_iteration(model, tolerance=1e-9)

    # V(low-obs, budget=0, p=0.0) = 1.0 (DELETE), V(high-obs, budget=0, p=0.1) = 5.0 (TERMINATE).
    # INSPECT = 0.25 + 0.9*1.0 + 0.1*5.0 = 1.65 < 5.0 (TERMINATE) < 11.0 (DELETE direct).
    assert greedy_action(policy, model.initial_state) == "INSPECT_NEXT"
    assert values[model.initial_state] == pytest.approx(1.65, abs=1e-9)

    low_observation_state = TMDPState(
        progress=0,
        candidate_index=0,
        observable_risk_bin="low",
        p_catastrophic=0.0,
        prior_warnings=0,
        remaining_budget=0,
        terminal=None,
    )
    high_observation_state = TMDPState(
        progress=0,
        candidate_index=0,
        observable_risk_bin="high",
        p_catastrophic=0.1,
        prior_warnings=1,
        remaining_budget=0,
        terminal=None,
    )
    assert greedy_action(policy, low_observation_state) == "DELETE_NEXT"
    assert greedy_action(policy, high_observation_state) == "TERMINATE"


def test_inspect_observations_update_belief_without_revealing_hidden_label():
    # Posteriors calibrated: 0.2*0.0 + 0.3*0.5 + 0.5*0.7 = 0.50 == prior.
    model = TMDPModel.single_candidate(
        p_catastrophic=0.5,
        observable_risk_bin="medium",
        inspection_observations={"low": (0.2, 0.0), "medium": (0.3, 0.5), "high": (0.5, 0.7)},
        catastrophe_cost=1000.0,
        termination_cost=5.0,
        inspect_step_cost=0.25,
    )

    transitions = model.transitions(model.initial_state, "INSPECT_NEXT")

    assert [(t.probability, t.next_state.observable_risk_bin, t.next_state.p_catastrophic) for t in transitions] == [
        (0.2, "low", 0.0),
        (0.3, "medium", 0.5),
        (0.5, "high", 0.7),
    ]
    assert all(t.cost == 0.25 for t in transitions)
    assert all(t.next_state.candidate_index == model.initial_state.candidate_index for t in transitions)
