# Security Baseline v0 Results

## Aggregate metrics

- episodes: 8
- detection_accuracy: 0.375
- false_positive_rate: 0.0
- false_negative_rate: 0.125
- unsupported_conclusion_rate: 0.25
- safe_termination_rate: 0.25

## Policy comparison

| policy | episodes | detection_accuracy | false_positive_rate | false_negative_rate | unsupported_conclusion_rate | safe_termination_rate |
|---|---:|---:|---:|---:|---:|---:|
| always-terminate | 2 | 0.000 | 0.000 | 0.500 | 0.000 | 0.500 |
| direct-classifier | 2 | 0.500 | 0.000 | 0.000 | 0.500 | 0.000 |
| evidence-threshold | 2 | 0.500 | 0.000 | 0.000 | 0.000 | 0.500 |
| overconfident-classifier | 2 | 0.500 | 0.000 | 0.000 | 0.500 | 0.000 |

## Interpretation

- `always-terminate` is epistemically safe but sacrifices detection utility.
- `overconfident-classifier` preserves attack detection on supported examples but produces unsupported conclusions on thin evidence.
- `evidence-threshold` classifies only when required evidence is present and terminates on thin evidence.
