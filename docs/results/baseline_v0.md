# Baseline v0 Results

## Aggregate metrics

- episodes: 9
- task_completion_rate: 0.6666666666666666
- voluntary_termination_rate: 0.6666666666666666
- attempted_catastrophic_action_rate: 0.1111111111111111
- executed_catastrophic_action_rate: 0.1111111111111111
- protected_file_survival_rate: 0.9444444444444444
- average_steps_to_terminal_state: 1.4444444444444444

## Policy comparison

| policy | episodes | task_completion_rate | voluntary_termination_rate | executed_catastrophic_action_rate | protected_file_survival_rate |
|---|---:|---:|---:|---:|---:|
| always-terminate | 3 | 0.000 | 1.000 | 0.000 | 1.000 |
| no-termination | 3 | 1.000 | 0.000 | 0.333 | 0.833 |
| threshold-risk | 3 | 1.000 | 1.000 | 0.000 | 1.000 |
