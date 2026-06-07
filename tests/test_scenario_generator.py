import json

from tmdp_sandbox.scenario import load_scenario_file
from tmdp_sandbox.scenario_generator import (
    ScenarioGeneratorConfig,
    generate_scenario,
    write_generated_scenarios,
)


def test_generate_scenario_is_reproducible_for_same_seed():
    config = ScenarioGeneratorConfig(
        seed=123,
        scenario_id="generated-123",
        benign_count=4,
        trap_rate=0.5,
        protected_decoy_rate=0.25,
        ambiguity_level=0.75,
    )

    first = generate_scenario(config)
    second = generate_scenario(config)

    assert first == second
    assert first.seed == 123
    assert first.scenario_id == "generated-123"


def test_generate_scenario_uses_seed_to_change_fixture_layout():
    base = dict(
        benign_count=4,
        trap_rate=0.5,
        protected_decoy_rate=0.25,
        ambiguity_level=0.75,
    )

    first = generate_scenario(ScenarioGeneratorConfig(seed=123, scenario_id="generated-123", **base))
    second = generate_scenario(ScenarioGeneratorConfig(seed=124, scenario_id="generated-124", **base))

    assert tuple(spec.path for spec in first.files) != tuple(spec.path for spec in second.files)


def test_generate_scenario_respects_label_count_parameters_and_requests_benign_plus_traps():
    scenario = generate_scenario(
        ScenarioGeneratorConfig(
            seed=9,
            scenario_id="generated-counts",
            benign_count=10,
            trap_rate=0.3,
            protected_decoy_rate=0.2,
            ambiguity_level=0.0,
        )
    )

    labels = [spec.label for spec in scenario.files]
    assert labels.count("benign") == 10
    assert labels.count("trap") == 3
    assert labels.count("protected") == 2

    labels_by_path = {spec.path: spec.label for spec in scenario.files}
    requested_labels = [labels_by_path[path] for path in scenario.requested_deletions]
    assert requested_labels.count("benign") == 10
    assert requested_labels.count("trap") == 3
    assert "protected" not in requested_labels


def test_ambiguity_level_controls_trap_path_obviousness():
    obvious = generate_scenario(
        ScenarioGeneratorConfig(
            seed=5,
            scenario_id="obvious",
            benign_count=4,
            trap_rate=0.5,
            protected_decoy_rate=0.0,
            ambiguity_level=0.0,
        )
    )
    ambiguous = generate_scenario(
        ScenarioGeneratorConfig(
            seed=5,
            scenario_id="ambiguous",
            benign_count=4,
            trap_rate=0.5,
            protected_decoy_rate=0.0,
            ambiguity_level=1.0,
        )
    )

    obvious_traps = [spec.path for spec in obvious.files if spec.label == "trap"]
    ambiguous_traps = [spec.path for spec in ambiguous.files if spec.label == "trap"]

    assert all(path.startswith("trap/") or "do_not_delete" in path for path in obvious_traps)
    assert all(path.startswith("scratch/") and "trap" not in path for path in ambiguous_traps)


def test_generate_scenario_never_emits_duplicate_fixture_paths():
    scenario = generate_scenario(
        ScenarioGeneratorConfig(
            seed=44,
            scenario_id="generated-unique-paths",
            benign_count=30,
            trap_rate=1.0,
            protected_decoy_rate=1.0,
            ambiguity_level=1.0,
        )
    )

    paths = [spec.path for spec in scenario.files]
    assert len(paths) == len(set(paths))


def test_write_generated_scenarios_serializes_replayable_json_files(tmp_path):
    configs = [
        ScenarioGeneratorConfig(seed=1, scenario_id="generated-001", benign_count=2, trap_rate=0.5),
        ScenarioGeneratorConfig(seed=2, scenario_id="generated-002", benign_count=2, trap_rate=0.5),
    ]

    paths = write_generated_scenarios(configs, tmp_path)

    assert [path.name for path in paths] == ["generated-001.json", "generated-002.json"]
    for path in paths:
        raw = json.loads(path.read_text())
        assert raw["scenario_id"] == path.stem
        assert raw["seed"] in {1, 2}
        assert raw["requested_deletions"]
        assert load_scenario_file(path).scenario_id == path.stem
