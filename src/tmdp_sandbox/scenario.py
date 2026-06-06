"""Scenario schema for deterministic file-deletion sandbox episodes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


_ALLOWED_LABELS = {"benign", "protected", "trap"}


@dataclass(frozen=True)
class FileSpec:
    """A fixture file to create under an episode temp root."""

    path: str
    label: str
    content: str = ""

    def __post_init__(self) -> None:
        _validate_relative_fixture_path(self.path)
        if self.label not in _ALLOWED_LABELS:
            allowed = ", ".join(sorted(_ALLOWED_LABELS))
            raise ValueError(f"unknown file label {self.label!r}; expected one of: {allowed}")


@dataclass(frozen=True)
class SandboxScenario:
    """A deterministic sandbox scenario definition."""

    scenario_id: str
    seed: int
    user_instruction: str
    files: tuple[FileSpec, ...]
    expected_achievements: tuple[str, ...]
    catastrophic_outcomes: tuple[str, ...]
    safe_termination_criteria: tuple[str, ...]


def load_scenario(raw: Mapping[str, Any]) -> SandboxScenario:
    """Load and validate a scenario from a JSON-like mapping."""

    files = tuple(
        FileSpec(
            path=str(item["path"]),
            label=str(item["label"]),
            content=str(item.get("content", "")),
        )
        for item in raw.get("files", ())
    )
    return SandboxScenario(
        scenario_id=str(raw["scenario_id"]),
        seed=int(raw["seed"]),
        user_instruction=str(raw["user_instruction"]),
        files=files,
        expected_achievements=tuple(str(x) for x in raw.get("expected_achievements", ())),
        catastrophic_outcomes=tuple(str(x) for x in raw.get("catastrophic_outcomes", ())),
        safe_termination_criteria=tuple(str(x) for x in raw.get("safe_termination_criteria", ())),
    )


def load_scenario_file(path: Path) -> SandboxScenario:
    """Load and validate a scenario from a JSON file."""

    return load_scenario(json.loads(Path(path).read_text(encoding="utf-8")))


def _validate_relative_fixture_path(path: str) -> None:
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or not path or any(part == ".." for part in parsed.parts):
        raise ValueError(f"fixture path would escape sandbox root: {path!r}")
