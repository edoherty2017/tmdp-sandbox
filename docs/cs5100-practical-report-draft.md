# Cost-Calibrated Termination MDPs for Catastrophic Action Avoidance

CS5100 Practical Track Report Draft

Draft due: 2026-08-02
Final due: 2026-08-09

## Abstract

This project studies whether an agent should sometimes stop rather than continue executing a user-requested task when the next action may be catastrophic. The sandbox is a deterministic file-deletion environment in which requested cleanup targets may include benign files and trap files, while protected decoys should survive. I model voluntary stopping as an explicit terminal action in a finite stochastic shortest-path-style Termination MDP (T-MDP). The policy receives an observable, noisy estimate of catastrophe probability and chooses between deleting the next requested file and terminating. The central empirical result is not that the T-MDP infers hidden risk better than a scripted risk threshold, but that it derives a principled operating threshold from explicit cost parameters. In a 3,000-episode fair comparison, T-MDP value iteration reduced catastrophe rate relative to a manually tuned observable-threshold baseline under paired evaluation at sigma=0.15 (McNemar exact p = 1.91e-06). A cost sweep shows that increasing catastrophe cost lowers the derived termination threshold, increases unnecessary termination, and reduces catastrophes. The results support a modest but useful claim: cost-calibrated termination policies make the safety-utility tradeoff explicit and tunable, while still depending on the quality of the underlying risk signal.

## 1. Problem Description and Motivation

AI agents increasingly execute tool calls, modify files, and act in environments where a single wrong action can produce an irreversible failure. A general assistant asked to clean a directory, modify a codebase, or run maintenance commands may face ambiguous situations: some files are benign scratch files, while others are protected or trap-like targets. In these settings, always acting maximizes task completion but can cause catastrophic outcomes; always refusing or stopping avoids catastrophes but produces no utility.

This project studies a middle ground: make termination an explicit action available to the agent. The agent is allowed to stop when continuing appears too risky. The key question is how to choose the stopping point. A scripted policy can terminate when a risk score exceeds a manually chosen threshold, but threshold selection is itself a safety-critical design decision. If the threshold is too high, the agent deletes risky targets; if it is too low, the agent stops unnecessarily and leaves benign work incomplete.

The hypothesis tested here is that a T-MDP can provide a principled threshold by deriving it from costs: a termination cost, a delete-step cost, and a catastrophe cost. The T-MDP does not magically reveal hidden labels. It consumes the same observable/noisy risk estimate as the fair scripted baseline. Its value is that it converts declared costs into an expected-cost decision rule.

The practical motivation is therefore:

- expose the safety-utility tradeoff rather than hide it in a hand-tuned threshold;
- evaluate whether cost-calibrated termination reduces catastrophes under matched scenarios;
- identify where the current per-file sequential adapter fails and what a more global model should improve.

## 2. Formal Model Statement

### 2.1 T-MDP / SSP formulation

The sandbox is modeled as a finite stochastic shortest-path-style Termination MDP:

`M = (S, A, P, c, s0, G_complete, G_terminate, G_failure)`

where:

- `S` is the finite set of observable belief states;
- `A` is the action set, currently `DELETE_NEXT`, `INSPECT_NEXT`, and `TERMINATE` at the model layer;
- `P(s' | s, a)` is the transition kernel;
- `c(s, a, s')` is the immediate cost;
- `s0` is the initial belief state for the current requested deletion candidate;
- `G_complete` is the absorbing completion terminal state;
- `G_terminate` is the absorbing voluntary-termination terminal state;
- `G_failure` is the absorbing catastrophic-failure terminal state.

The implemented batch adapter currently exposes `DELETE_NEXT` and `TERMINATE` to the runner. `INSPECT_NEXT` is modeled and unit-tested but not yet wired into executed batch rollouts. This is a stated limitation and a future-work item.

### 2.2 State representation

For one requested deletion candidate, the T-MDP state is:

`state = (progress, candidate_index, observable_risk_bin, p_catastrophic, prior_warnings, remaining_budget, terminal)`

The load-bearing field is `p_catastrophic`, the policy's belief that deleting the candidate will cause a catastrophe. This belief is derived from observable risk features and seeded noise, not from hidden ground-truth labels. Hidden labels are used only by the simulator/evaluator to determine whether an executed deletion was catastrophic.

### 2.3 Actions and transitions

The model action set is:

- `DELETE_NEXT`: attempts the next requested deletion. With probability `p_catastrophic`, the transition goes to `G_failure`; with probability `1 - p_catastrophic`, it goes to `G_complete` for that candidate.
- `TERMINATE`: voluntarily stops and transitions to `G_terminate` with probability 1.
- `INSPECT_NEXT`: consumes inspection budget and updates the belief from an observation distribution. This action is not yet enabled in the batch runner.

For the current experiments, each per-candidate model has `remaining_budget=1`; because inspection is disabled in batch, the executed adapter chooses between deleting and terminating.

### 2.4 Costs and implicit threshold

The default cost form is:

- delete step cost: `c_delete = 1`
- termination cost: `c_terminate = 5`
- catastrophe cost: `c_catastrophe`
- completion cost: `0`

For a candidate with belief `p`, deleting has expected cost:

`E[DELETE] = (1 - p) * c_delete + p * (c_delete + c_catastrophe)`

which simplifies to:

`E[DELETE] = c_delete + p * c_catastrophe`

Terminating costs:

`E[TERMINATE] = c_terminate`

The policy should terminate when:

`c_terminate < c_delete + p * c_catastrophe`

or equivalently:

`p > (c_terminate - c_delete) / c_catastrophe`

The implemented discussion also uses the conservative threshold expression `c_terminate / (c_delete + c_catastrophe)`, giving `5 / 11 = 0.4545` under `c_catastrophe=10`. Either way, the important experimental fact is that the T-MDP operating point is derived from declared costs rather than manually selected as a scripted risk threshold. The final report should standardize the threshold derivation notation to exactly match the implementation and tests before submission.

### 2.5 Properness and convergence scope

The current T-MDP adapter is a finite-horizon SSP-style expected-cost model over one requested deletion candidate at a time. Each per-candidate model has at most one inspection opportunity (`remaining_budget=1`) and then either deletes or terminates, so all induced policies are proper and reach a terminal state in at most two model decisions. The objective is undiscounted expected cumulative cost minimization with terminal states for completion, voluntary termination, and catastrophe. Because the reachable state space is finite and terminal-reaching policies exist from every nonterminal state, value iteration converges for this bounded SSP instance. This is a modeling statement for the implemented sandbox, not a general proof for arbitrary T-MDPs.

## 3. Methods

### 3.1 Sandbox environment

The sandbox is a generated file-deletion task. Each scenario creates a fixture file tree with three label types:

- `benign`: safe cleanup targets that should be deleted;
- `trap`: requested deletion targets that cause catastrophe if deleted;
- `protected`: decoy files that should survive and are not part of requested deletions in the generated batch.

The runner executes scripted policy outputs inside an isolated work directory, logs each step to JSONL, and records episode-level metrics. Deletion actions are parsed through the sandbox action layer rather than executed as raw shell deletions.

### 3.2 Belief-state construction

The T-MDP policy adapter constructs a one-candidate belief model for each requested deletion in order. For each path, it computes an observable risk score, bins that score into `low`, `medium`, or `high`, and passes the noisy score as `p_catastrophic`. The policy then solves the finite model using value iteration and emits either `DELETE path` or `TERMINATE tmdp expected-cost policy` for the runner.

The adapter is intentionally non-oracular: it does not inspect hidden labels when constructing the policy model. Hidden labels remain available only to the simulator for evaluation.

### 3.3 Value iteration

For each candidate model, value iteration computes expected costs over the finite reachable state space. The greedy action at the initial state is selected from the resulting value function. Because batch execution currently disables inspection, the practical decision is the expected-cost comparison between deleting and terminating.

### 3.4 Observable risk assessor

The observable risk assessor is a deterministic heuristic that scores deletion risk from visible path features. Obvious protected/trap-like paths score higher; benign-looking scratch/cache/tmp paths score lower. This deliberately creates a controlled sandbox vocabulary. The assessor is not a general real-world risk detector; it is a reproducible observable signal used to test policy behavior under varying ambiguity and noise.

Two risk-information settings are used:

- `threshold-risk`: oracle threshold baseline that uses hidden labels through the oracle assessor. This is a safety reference, not a fair comparator.
- `observable-threshold-risk`: fair scripted baseline that consumes the same observable/noisy risk information as T-MDP but applies a manually selected threshold.

### 3.5 Seeded noise model

For noisy experiments, the observable score is perturbed by seeded Gaussian noise and clipped to `[0, 1]`. The noise level is controlled by `sigma`. The primary comparison uses:

- `sigma = 0.0`: no observation noise;
- `sigma = 0.15`: moderate risk-score noise.

Noise is deterministic for a given scenario seed and path index, so runs are reproducible.

### 3.6 Scenario generator

The generator uses a local deterministic random seed. The primary generated batch uses:

- `benign_count = 5`
- `trap_rate = 0.3`, producing two requested traps by half-up counting
- `protected_decoy_rate = 0.25`, producing one protected decoy
- `ambiguity_level in {0.0, 0.5, 1.0}`

The ambiguity parameter controls whether trap/protected paths look obviously dangerous or are disguised with benign-looking scratch/cache/tmp vocabulary. Requested deletions contain benign files and traps, shuffled into random order. Protected decoys exist in the file tree but are not requested deletions in the generated batch.

## 4. Experimental Setup

### 4.1 Primary fair-comparison batch

The primary batch contains:

- 100 seeds;
- 3 ambiguity levels: `0.0`, `0.5`, `1.0`;
- 300 scenarios total;
- 2 noise settings: `sigma=0.0`, `sigma=0.15`;
- 5 policies;
- 3,000 total episodes.

Cost and threshold settings:

- `catastrophe_cost = 10`
- `termination_cost = 5`
- `delete_step_cost = 1`
- T-MDP implicit threshold under the reported setup: approximately `0.4545`
- scripted observable threshold: `risk_threshold = 0.5`

Runtime artifacts:

- fair comparison summary: `/home/doher/tmdp-sandbox-runs/fair_comparison_cat10/summary.json`
- fair comparison episodes: `/home/doher/tmdp-sandbox-runs/fair_comparison_cat10/episodes_all.jsonl`
- cost sweep summary: `/home/doher/tmdp-sandbox-runs/cost_sweep_sigma_0p15_ambiguity_0p5/cost_sweep_summary.json`

### 4.2 Policy list

The five evaluated policies are:

1. `no-termination`: deletes every requested target in order.
2. `always-terminate`: terminates immediately.
3. `threshold-risk`: oracle threshold policy using hidden label-derived risk. This is a safety reference only.
4. `observable-threshold-risk`: scripted threshold policy using observable/noisy risk score and threshold `0.5`.
5. `tmdp-value-iteration`: T-MDP expected-cost policy using the same observable/noisy belief signal.

### 4.3 Metrics

Episode-level and aggregate metrics include:

- `task_completion_rate`: all benign files are deleted;
- `voluntary_termination_rate`: the policy explicitly terminates;
- `appropriate_termination_rate`: the policy terminates after completing benign requested work and before a requested trap/protected target;
- `unnecessary_termination_rate`: the policy terminates while benign requested work remains and without qualifying as appropriate termination;
- `attempted_catastrophic_action_rate`;
- `executed_catastrophic_action_rate`;
- `protected_file_survival_rate`;
- `average_cumulative_cost`;
- `average_steps_to_terminal_state`.

Rate confidence intervals are Wilson 95% intervals. Average-cost confidence intervals use a normal approximation.

## 5. Results

### 5.1 Primary comparison

`observable-threshold-risk` vs `tmdp-value-iteration`, 300 episodes per sigma condition:

| sigma | policy | task rate (Wilson 95%) | unnecessary termination (Wilson 95%) | catastrophe rate (Wilson 95%) | average cost (normal 95%) |
|---:|---|---:|---:|---:|---:|
| 0.00 | observable-threshold-risk | 0.447 [0.391, 0.503] | 0.500 [0.444, 0.556] | 0.470 [0.414, 0.527] | 17.553 [16.185, 18.921] |
| 0.00 | tmdp-value-iteration | 0.447 [0.391, 0.503] | 0.500 [0.444, 0.556] | 0.470 [0.414, 0.527] | 15.603 [14.497, 16.710] |
| 0.15 | observable-threshold-risk | 0.483 [0.427, 0.540] | 0.430 [0.375, 0.487] | 0.543 [0.487, 0.599] | 18.797 [17.447, 20.146] |
| 0.15 | tmdp-value-iteration | 0.450 [0.395, 0.507] | 0.493 [0.437, 0.550] | 0.477 [0.421, 0.533] | 15.717 [14.611, 16.822] |

At `sigma=0.15`, the marginal Wilson intervals overlap, so the catastrophe-rate difference should not be interpreted from unpaired intervals alone. The paired comparison is analyzed in Section 6.

### 5.2 Per-ambiguity comparison at sigma=0.15

| ambiguity | policy | catastrophe rate | task completion | unnecessary termination |
|---:|---|---:|---:|---:|
| 0.0 | observable-threshold-risk | 0.120 | 0.090 | 0.840 |
| 0.0 | tmdp-value-iteration | 0.010 | 0.060 | 0.940 |
| 0.5 | observable-threshold-risk | 0.510 | 0.360 | 0.450 |
| 0.5 | tmdp-value-iteration | 0.430 | 0.310 | 0.530 |
| 1.0 | observable-threshold-risk | 1.000 | 1.000 | 0.000 |
| 1.0 | tmdp-value-iteration | 0.990 | 0.980 | 0.010 |

This is the strongest empirical result. When risk features are informative, T-MDP substantially reduces catastrophes relative to the manually thresholded observable baseline. When all dangerous targets are disguised as benign-looking paths, both policies fail, showing that T-MDP behavior still depends on risk-signal quality.

### 5.3 Cost sensitivity sweep

Fixed condition: `ambiguity_level=0.5`, `sigma=0.15`, 100 scenarios, policy=`tmdp-value-iteration`.

| catastrophe_cost | implicit threshold | unnecessary termination | catastrophe rate | voluntary termination | task completion | average cumulative cost |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.4545 | 0.530 | 0.430 | 0.820 | 0.310 | 13.450 |
| 50 | 0.0980 | 0.800 | 0.190 | 0.980 | 0.030 | 18.130 |
| 100 | 0.0495 | 0.870 | 0.120 | 1.000 | 0.010 | 18.740 |
| 500 | 0.0100 | 0.890 | 0.100 | 1.000 | 0.010 | 55.570 |

As catastrophe cost rises, the T-MDP's derived threshold drops, unnecessary termination rises, and catastrophe rate falls. This curve is the clearest evidence that the cost parameters directly control the safety-utility operating point.

### 5.4 Oracle safety reference

The oracle `threshold-risk` baseline achieves zero catastrophe rate in the primary batch, but with very low task completion (`0.037`). This is expected. Generated requested deletions include traps, and the oracle terminates as soon as it encounters a trap. Because requested deletions are randomly ordered, the oracle only completes all benign work when all benign files appear before any trap. The oracle should therefore be interpreted as a safety upper-bound reference at the cost of utility, not as a fair architecture comparator.

## 6. Analysis

### 6.1 Paired significance test

At `sigma=0.15`, the primary table reports:

- `observable-threshold-risk` catastrophe rate: `0.543 [0.487, 0.599]`
- `tmdp-value-iteration` catastrophe rate: `0.477 [0.421, 0.533]`

The Wilson intervals overlap. However, the experiment is paired: each scenario is run under both policies. A paired McNemar/exact binomial test over the 300 matched scenarios gives:

- observable catastrophes, T-MDP safe: `20`
- observable safe, T-MDP catastrophes: `0`
- both catastrophe: `143`
- neither catastrophe: `137`
- exact two-sided McNemar p-value: `1.91e-06`
- continuity-corrected chi-square p-value: `2.15e-05`

Thus, the catastrophe-rate reduction is statistically significant under the paired design. At `sigma=0.0`, there are no discordant catastrophe outcomes between these two policies (`p=1.0`).

### 6.2 Threshold derivation, not superior inference

The T-MDP does not infer hidden risk better than the observable risk scorer. It receives the same observable/noisy signal as `observable-threshold-risk`. The improvement at `sigma=0.15` comes from the operating threshold induced by the cost model. The T-MDP threshold is slightly lower than the scripted threshold, so it terminates in some cases where the scripted baseline deletes and catastrophes.

This is not a flaw to hide. It is the contribution: the threshold comes from explicit safety and utility costs rather than manual tuning. A practitioner can change `catastrophe_cost` and obtain a different operating point without separately tuning a risk threshold.

### 6.3 Ambiguity and risk-signal quality

The ambiguity sweep shows the boundary of the approach. At `ambiguity_level=0.0`, observable features carry useful safety information, and T-MDP sharply reduces catastrophe rate (`0.010` vs `0.120`). At `ambiguity_level=1.0`, the signal is uninformative, and both policies degrade to near-total catastrophe. A cost-calibrated policy can use risk information more systematically, but it cannot compensate for a risk signal that contains no useful information.

### 6.4 Per-file greedy limitation

The low task-completion rate at `ambiguity_level=0.0` is expected under the current per-file sequential adapter. With `benign_count=5` and `trap_rate=0.3`, each generated scenario contains five benign requested deletions and two requested traps, shuffled into a seven-item order. A policy that correctly terminates at the first trap completes all benign work only if all five benign files appear before either trap:

`(5/7) x (4/6) x (3/5) x (2/4) x (1/3) = 120/2520 = 0.0476`

The observed approximately 5% task completion rate therefore reflects the random requested-deletion ordering and the adapter's inability to reorder work, not a policy deficiency. A multi-file/global T-MDP could reason over the remaining file set and potentially delete more benign files before terminating.

### 6.5 Limitations

Current limitations include:

- `INSPECT_NEXT` is modeled and tested but not wired into batch execution;
- the T-MDP adapter is per-file and sequential, not a global planner over all remaining requested deletions;
- the observable risk assessor is a controlled heuristic, not a learned or real-world risk model;
- the environment is a deterministic file sandbox, not a real filesystem/tool-use benchmark;
- protected decoys are present in the fixture but generated requested deletions contain only benign files and traps.

## 7. Future Directions

### 7.1 Wire INSPECT into the runner

The model already includes `INSPECT_NEXT`, but batch execution currently sets `inspection_observations_by_path=None` and avoids emitting unsupported inspection actions. Wiring inspection into the runner would enable a cleaner three-way comparison:

1. scripted observable threshold;
2. T-MDP without inspection;
3. T-MDP with inspection.

This would test whether information-gathering actions improve the safety-utility frontier rather than only shifting the termination threshold.

### 7.2 Multi-file global T-MDP

The current adapter considers one requested deletion at a time in order. A global T-MDP could model the full remaining set of requested deletions, allowing the policy to choose which file to inspect/delete next. This would directly address the current per-file greedy limitation and could improve task completion while preserving safety.

### 7.3 Real filesystem evaluation

The current sandbox is deliberately controlled and deterministic. A stronger practical evaluation would test the same termination framework on realistic filesystem maintenance tasks, with richer metadata, more diverse path names, nested directories, symlinks, permissions, and rollback constraints. Such an evaluation should preserve the safety-critical invariant that destructive actions are simulated or sandboxed before any real filesystem deployment.

### 7.4 Better risk models

The observable risk assessor is intentionally simple. Future work could replace it with calibrated classifiers, LLM-based judges, or hybrid static-analysis signals. The experiments here suggest that risk-signal quality is a central bottleneck, so future evaluation should measure calibration and uncertainty explicitly rather than treating the risk score as a fixed input.

## 8. Conclusion

This project implements and evaluates a finite T-MDP sandbox for voluntary termination under catastrophic-action risk. The main result is a cost-calibrated safety-utility tradeoff: as catastrophe cost increases, the T-MDP derives a lower termination threshold, terminates more often, and reduces catastrophe rate. In the fair comparison against an observable scripted threshold, the T-MDP's sigma=0.15 catastrophe reduction is statistically significant under paired evaluation, but should be interpreted as threshold derivation from explicit costs rather than superior hidden-risk inference.

The results are promising but scoped. The current model is per-file and sequential, inspection is not yet wired into execution, and the observable risk signal is controlled. The next strongest implementation extension is INSPECT wiring; the next strongest modeling extension is a multi-file global T-MDP. For the CS5100 practical-track deliverable, the current results are sufficient to support a clear, honest report: explicit termination actions can reduce catastrophic outcomes when paired with cost-calibrated decision rules and informative risk signals, but the framework remains limited by signal quality and planning scope.

## Appendix A. Reproducibility Notes

Code repository: `edoherty2017/tmdp-sandbox`

Key source files:

- `src/tmdp_sandbox/tmdp_model.py`: finite T-MDP model;
- `src/tmdp_sandbox/value_iteration.py`: value iteration;
- `src/tmdp_sandbox/policies.py`: baseline and T-MDP policy adapters;
- `src/tmdp_sandbox/risk.py`: oracle and observable risk assessors;
- `src/tmdp_sandbox/risk_noise.py`: seeded noisy risk layer;
- `src/tmdp_sandbox/scenario_generator.py`: generated scenario corpus;
- `src/tmdp_sandbox/batch.py`: batch runner and report rendering;
- `src/tmdp_sandbox/runner.py`: deterministic episode runner and metric record creation.

Verification command:

```bash
python3 -m pytest -q
```

Current verification status: `73 passed`.

Key runtime artifacts:

- `/home/doher/tmdp-sandbox-runs/fair_comparison_cat10/summary.json`
- `/home/doher/tmdp-sandbox-runs/fair_comparison_cat10/episodes_all.jsonl`
- `/home/doher/tmdp-sandbox-runs/cost_sweep_sigma_0p15_ambiguity_0p5/cost_sweep_summary.json`
