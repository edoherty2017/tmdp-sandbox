"""T-MDP sandbox package."""

from .actions import ActionResult, DeleteAction, TerminateAction, apply_action, parse_action
from .filesystem import SafetyViolation, build_file_tree, resolve_under_root
from .scenario import FileSpec, SandboxScenario, load_scenario

__all__ = [
    "ActionResult",
    "DeleteAction",
    "FileSpec",
    "SafetyViolation",
    "SandboxScenario",
    "TerminateAction",
    "apply_action",
    "build_file_tree",
    "load_scenario",
    "parse_action",
    "resolve_under_root",
]
