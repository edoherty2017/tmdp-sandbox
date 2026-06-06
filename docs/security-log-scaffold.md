# Security-log agent scaffold

This is the first security-log version of the same terminating-agent idea used in the deterministic file sandbox.

## Scenario record

Security-log scenarios use JSON files with:

- `scenario_id`
- `seed`
- `user_instruction`
- `events`
  - `event_id`
  - `source`
  - `message`
- `ground_truth`: one of `attack`, `benign`, or `unknown`
- `attack_type`: attack family such as `privilege_escalation`, or `none`
- `required_evidence`: evidence fragments required before an attack classification is supported
- `uncertainty_triggers`: missing/contextual signals that should encourage request-more-evidence or termination

Example scenario files live under `examples/security_logs/`.

## Actions

Initial policy output language:

- `CLASSIFY_ATTACK <attack_type>`
- `REQUEST_MORE_EVIDENCE <reason>`
- `TERMINATE <reason>`

`TERMINATE` is the direct security-log analogue of the file sandbox's self-termination action. It is appropriate when evidence is insufficient and the ground-truth label is `unknown`.

## Metrics

Security-log episode metrics include:

- `detection_accuracy`
- `false_positive_rate`
- `false_negative_rate`
- `unsupported_conclusion_rate`
- `safe_termination_rate`

The most important safety metric at this stage is `unsupported_conclusion_rate`: an overconfident agent should be penalized for asserting an attack when required evidence is missing, even if the attack type is plausible.

## Baseline security experiments

Security baseline experiments run normalized security-log scenarios across deterministic policies:

- `direct-classifier`: directly classifies the scenario's attack type.
- `always-terminate`: always emits `TERMINATE`.
- `evidence-threshold`: classifies only when all required evidence fragments are present; otherwise terminates.
- `overconfident-classifier`: always classifies the attack type even when evidence is thin.

The batch runner writes:

- `aggregate_metrics.json`
- `episodes.jsonl`
- per-episode rollout JSONL files under `rollouts/`
- `security_baseline_v0.md`

The current static result snapshot is committed at `docs/results/security_baseline_v0.md`.

## Initial design intent

The first security-log scaffold does not parse EVTX directly yet. It represents small normalized event excerpts from candidate sources such as Security Datasets and EVTX-ATTACK-SAMPLES. This keeps the pre-proposal implementation deterministic and inspectable while preserving the intended task shape: classify attack evidence, request more information, or terminate safely under uncertainty.
