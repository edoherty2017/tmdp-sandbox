"""Event and scenario types for the security command classification domain."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

_ALLOWED_LABELS = {"benign", "malicious"}


@dataclass(frozen=True)
class EventSpec:
    """A single system event or command the agent must decide on.

    `label` is the ground-truth classification used only by the evaluator.
    The classifier and T-MDP policy never receive it directly.
    """

    process_name: str
    command_line: str
    user_name: str
    parent_process: str
    event_id: int | None = None
    label: str = "benign"
    raw_log: str = ""

    def __post_init__(self) -> None:
        if self.label not in _ALLOWED_LABELS:
            allowed = ", ".join(sorted(_ALLOWED_LABELS))
            raise ValueError(f"unknown event label {self.label!r}; expected one of: {allowed}")


@dataclass(frozen=True)
class SecurityScenario:
    """An ordered sequence of events the agent processes in a single episode.

    `requested_executions` is the tuple of indices into `events` that the agent
    must decide on (execute / block / defer). Events not in this list are context
    only — they inform the context window but do not require a decision.
    """

    scenario_id: str
    seed: int
    events: tuple[EventSpec, ...]
    requested_executions: tuple[int, ...]

    def __post_init__(self) -> None:
        n = len(self.events)
        for idx in self.requested_executions:
            if not (0 <= idx < n):
                raise ValueError(
                    f"requested_execution index {idx} out of range for {n} events"
                )

    @property
    def decision_events(self) -> tuple[EventSpec, ...]:
        return tuple(self.events[i] for i in self.requested_executions)


def load_security_scenario(raw: Mapping[str, Any]) -> SecurityScenario:
    events = tuple(
        EventSpec(
            process_name=str(item.get("process_name", "")),
            command_line=str(item.get("command_line", "")),
            user_name=str(item.get("user_name", "")),
            parent_process=str(item.get("parent_process", "")),
            event_id=int(item["event_id"]) if item.get("event_id") is not None else None,
            label=str(item.get("label", "benign")),
            raw_log=str(item.get("raw_log", "")),
        )
        for item in raw.get("events", ())
    )
    return SecurityScenario(
        scenario_id=str(raw["scenario_id"]),
        seed=int(raw["seed"]),
        events=events,
        requested_executions=tuple(int(i) for i in raw.get("requested_executions", ())),
    )


def load_security_scenario_file(path: Path) -> SecurityScenario:
    return load_security_scenario(json.loads(Path(path).read_text(encoding="utf-8")))
