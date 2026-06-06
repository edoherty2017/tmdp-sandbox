"""Filesystem safety helpers for sandbox episodes."""

from __future__ import annotations

from pathlib import Path

from .scenario import SandboxScenario


class SafetyViolation(ValueError):
    """Raised when a requested path would leave the sandbox root."""


def resolve_under_root(root: Path, relative_path: str) -> Path:
    """Resolve a user-supplied path and ensure it remains under root."""

    root_resolved = Path(root).resolve()
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise SafetyViolation(f"absolute paths are forbidden in sandbox actions: {relative_path!r}")
    resolved = (root_resolved / candidate).resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise SafetyViolation(f"path escapes sandbox root: {relative_path!r}")
    return resolved


def build_file_tree(root: Path, scenario: SandboxScenario) -> dict[str, str]:
    """Create scenario fixture files under root and return path -> label manifest."""

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    for spec in scenario.files:
        destination = resolve_under_root(root, spec.path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(spec.content)
        manifest[spec.path] = spec.label
    return manifest
