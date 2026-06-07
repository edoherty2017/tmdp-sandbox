import pytest

from tmdp_sandbox.risk_noise import apply_noise, calibrated_inspection_observations
from tmdp_sandbox.tmdp_model import TMDPModel


def test_apply_noise_is_reproducible_for_same_seed():
    first = apply_noise(base_score=0.4, seed=123, sigma=0.2)
    second = apply_noise(base_score=0.4, seed=123, sigma=0.2)

    assert first == second


def test_apply_noise_changes_with_seed_when_sigma_positive():
    first = apply_noise(base_score=0.4, seed=123, sigma=0.2)
    second = apply_noise(base_score=0.4, seed=124, sigma=0.2)

    assert first != second


def test_apply_noise_sigma_zero_returns_base_score():
    assert apply_noise(base_score=0.4, seed=123, sigma=0.0) == 0.4


def test_apply_noise_clamps_to_unit_interval():
    assert 0.0 <= apply_noise(base_score=0.0, seed=1, sigma=10.0) <= 1.0
    assert 0.0 <= apply_noise(base_score=1.0, seed=2, sigma=10.0) <= 1.0


@pytest.mark.parametrize("prior", [0.0, 0.01, 0.25, 0.5, 0.9, 1.0])
def test_calibrated_inspection_observations_match_prior_exactly(prior):
    observations = calibrated_inspection_observations(prior, delta=0.2)

    expected = sum(probability * posterior for probability, posterior in observations.values())
    assert expected == pytest.approx(prior, abs=1e-12)
    TMDPModel.single_candidate(
        p_catastrophic=prior,
        observable_risk_bin="medium",
        inspection_observations=observations,
    )


def test_calibrated_inspection_observations_create_low_and_high_signal_when_possible():
    observations = calibrated_inspection_observations(0.4, delta=0.2)

    low_probability, low_posterior = observations["low"]
    high_probability, high_posterior = observations["high"]

    assert low_probability > 0.0
    assert high_probability > 0.0
    assert low_posterior < 0.4 < high_posterior
