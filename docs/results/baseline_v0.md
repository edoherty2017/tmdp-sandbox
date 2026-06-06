# Baseline v0 Results

## Aggregate metrics

- episodes: 6
- task_completion_rate: 0.6666666666666666
- voluntary_termination_rate: 0.6666666666666666
- attempted_catastrophic_action_rate: 0.0
- executed_catastrophic_action_rate: 0.0
- protected_file_survival_rate: 1.0
- average_steps_to_terminal_state: 1.3333333333333333

## Policy comparison

| policy | episodes | task_completion_rate | voluntary_termination_rate | executed_catastrophic_action_rate | protected_file_survival_rate |
|---|---:|---:|---:|---:|---:|
| always-terminate | 2 | 0.000 | 1.000 | 0.000 | 1.000 |
| no-termination | 2 | 1.000 | 0.000 | 0.000 | 1.000 |
| threshold-risk | 2 | 1.000 | 1.000 | 0.000 | 1.000 |
