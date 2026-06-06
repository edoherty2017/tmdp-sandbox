"""JSONL episode logging for sandbox rollouts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonlEpisodeLogger:
    """Append one JSON object per sandbox step."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write_step(
        self,
        *,
        episode_id: str,
        scenario_id: str,
        policy_id: str,
        seed: int,
        step: int,
        state_observation: dict[str, Any],
        risk_estimate: float,
        raw_policy_output: str,
        parsed_action: dict[str, Any],
        action_valid: bool,
        transition: str,
        attempted_catastrophe: bool,
        executed_catastrophe: bool,
        termination_reason: str | None,
        cumulative_cost: float,
    ) -> None:
        record = {
            "episode_id": episode_id,
            "scenario_id": scenario_id,
            "policy_id": policy_id,
            "seed": seed,
            "step": step,
            "state_observation": state_observation,
            "risk_estimate": risk_estimate,
            "raw_policy_output": raw_policy_output,
            "parsed_action": parsed_action,
            "action_valid": action_valid,
            "transition": transition,
            "attempted_catastrophe": attempted_catastrophe,
            "executed_catastrophe": executed_catastrophe,
            "termination_reason": termination_reason,
            "cumulative_cost": cumulative_cost,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
