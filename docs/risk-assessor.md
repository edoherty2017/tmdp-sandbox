# Risk Assessor Interface

The sandbox now separates policy construction from risk estimation.

## Replayable assessment record

Each delete-risk estimate is represented as a `RiskAssessment` with:

- `assessor_id`: stable identifier for the assessor implementation/version.
- `action`: currently `DELETE` for file-sandbox candidates.
- `target_path`: scenario-relative target path.
- `score`: normalized risk score in `[0.0, 1.0]`.
- `rationale`: human-readable reason for the score.
- `raw_response`: optional raw external/LLM output; `null` for deterministic heuristics.
- `failure_mode`: optional parse/runtime failure label; `null` on clean assessment.

This keeps the deterministic heuristic baseline and any future LLM judge on the same logging contract.

## Current implementation

`HeuristicRiskAssessor` is deterministic and maps fixture labels to risk scores:

| label | risk score |
|---|---:|
| benign | 0.1 |
| protected | 0.9 |
| trap | 0.9 |

Unknown target paths return risk `1.0` with failure mode `unknown_target_path`.

## Policy integration

`build_baseline_policy(..., risk_assessor=...)` accepts an injected delete-risk assessor. If none is provided, it uses `HeuristicRiskAssessor`.

This preserves P5 sequencing:

1. deterministic heuristic assessor first;
2. external/LLM judge can be added later behind the same interface;
3. prompt/version/raw-response logging has an explicit place in the schema before any LLM judge is enabled.
