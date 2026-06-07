"""Seeded noise helpers for observable catastrophe-risk estimates."""

from __future__ import annotations

import random

from .tmdp_model import RiskBin


def apply_noise(*, base_score: float, seed: int, sigma: float) -> float:
    """Return a reproducible clipped Gaussian perturbation of base_score."""

    _validate_probability(base_score, "base_score")
    if sigma < 0.0:
        raise ValueError(f"sigma must be non-negative, got {sigma!r}")
    if sigma == 0.0:
        return base_score
    rng = random.Random(seed)
    return _clip_probability(base_score + rng.gauss(0.0, sigma))


def calibrated_inspection_observations(
    prior: float,
    *,
    delta: float = 0.2,
) -> dict[RiskBin, tuple[float, float]]:
    """Construct a two-outcome inspection table whose expected posterior is prior.

    The returned mapping satisfies the T-MDP belief-consistency invariant exactly:
    sum(P(obs_i) * posterior_i) == prior, up to floating-point roundoff. It uses
    lower and upper posteriors around the prior, then solves for the observation
    probabilities that make the posterior process a martingale.
    """

    _validate_probability(prior, "prior")
    if delta < 0.0 or delta > 1.0:
        raise ValueError(f"delta must be in [0, 1], got {delta!r}")
    if delta == 0.0 or prior in {0.0, 1.0}:
        risk_bin: RiskBin = "low" if prior < 1.0 / 3.0 else "high"
        return {risk_bin: (1.0, prior)}

    low_posterior = max(0.0, prior - delta)
    high_posterior = min(1.0, prior + delta)
    if high_posterior == low_posterior:
        return {"medium": (1.0, prior)}

    high_probability = (prior - low_posterior) / (high_posterior - low_posterior)
    low_probability = 1.0 - high_probability
    return {
        "low": (low_probability, low_posterior),
        "high": (high_probability, high_posterior),
    }


def _validate_probability(value: float, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {value!r}")


def _clip_probability(value: float) -> float:
    return max(0.0, min(1.0, value))
