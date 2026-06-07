# Panel Remediation Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Convert the current CS5100 T-MDP sandbox from a clean deterministic scaffold into an honest, research-bearing finite-state T-MDP experiment with value iteration, non-oracle risk estimates, stochastic/noisy scenarios, and termination-quality metrics.

**Architecture:** Keep the existing sandbox runner and JSONL logging as infrastructure, but introduce a separate finite-state T-MDP model layer that computes policies over observable states. Hidden labels remain available only to the simulator/evaluator, never to non-oracle policies. Scripted baselines remain as baselines; the title contribution becomes a real value-iteration policy.

**Tech Stack:** Python 3.10+, stdlib dataclasses/random/statistics, pytest, existing `src/tmdp_sandbox` package.

---

## Non-negotiable correction rules

1. No non-oracle policy may read `FileSpec.label` or any hidden label field.
2. `seed` must drive all randomized/noisy scenario generation and risk-estimator perturbations.
3. `TERMINATE` must have a positive opportunity cost; always-terminate must not be the cost-minimizing policy.
4. T-MDP value iteration must be implemented before claiming T-MDP results.
5. Scenario labels may be used by the environment transition/evaluation oracle only.
6. The security-log experiment must either be moved to archived/future-work docs or formally integrated later; it is out of the main pre-proposal claim.

## Gap map from panel review to repo files

- State/action/formulation disconnect:
  - Current: `runner.py` logs only `{"visible_files": sorted(manifest)}`.
  - Fix: add observable feature state in `scenario.py`/new `tmdp_model.py` and log it.
- Missing transition model:
  - Current: deterministic `apply_action` side effects only.
  - Fix: add explicit `P(s'|s,a)` in new `tmdp_model.py`, including stochastic/noisy risk observations.
- Oracle risk assessor:
  - Current: `HeuristicRiskAssessor` maps hidden labels to risk scores.
  - Fix: keep it only as `OracleLabelRiskAssessor` for sanity checks; add observable-feature and noisy-feature assessors.
- Missing T-MDP policy:
  - Current: `policies.py` has scripted baselines only.
  - Fix: add value iteration and policy adapter.
- Missing termination-quality metrics:
  - Current: `metrics.py` lacks `appropriate_termination_rate`, `unnecessary_termination_rate`, and cumulative cost.
  - Fix: add episode fields and metrics using safe-completion existence / catastrophe-prevention criteria.
- Trivial scale:
  - Current: `examples/scenarios` has 3 scenarios, 9 episodes.
  - Fix: add seeded scenario generator and batch sweeps.

---

## P1: Make the pre-proposal honest immediately

**Objective:** Avoid overclaiming before tomorrow's pre-proposal.

**Files:**
- Create: `docs/preproposal-status.md`
- Modify: `README.md`

**Required content:**
- State that current status is end of Step 2 / infrastructure scaffold.
- State that the basic algorithm is not yet complete.
- Identify next milestone as finite-state T-MDP value iteration using observable features.
- Identify following milestone as noisy-risk comparison against scripted baselines.
- Report current baseline results as smoke tests only, not evidence for the hypothesis.

**Verification:**
- `grep -n "smoke test\|value iteration\|observable" docs/preproposal-status.md README.md`
- Confirm no language says the current threshold-risk result validates H2/H3.

---

## Milestone assignment

- Milestone 1 due 2026-07-05: P4 is the primary target. A working finite-state T-MDP value-iteration policy must exist by M1, even if risk naming and scenario generation remain minimal.
- Milestone 2 due 2026-07-19: P5-P6 are the primary targets. Seeded stochastic scenario generation, noisy-risk sweeps, and statistical comparison belong here.
- P2/P3 are supporting cleanup/metrics work and should not block starting P4.

## P2: Rename/separate oracle risk from non-oracle risk

**Objective:** Prevent the current label lookup from masquerading as deployable risk estimation.

**Files:**
- Modify: `src/tmdp_sandbox/risk.py`
- Modify: `src/tmdp_sandbox/policies.py`
- Modify: `tests/test_risk_assessor.py`
- Create: `tests/test_non_oracle_risk.py`

**Implementation requirements:**
- Rename or wrap `HeuristicRiskAssessor` as an explicit oracle/sanity-check assessor.
- Add `ObservableFeatureRiskAssessor` that uses only path string, file extension, path depth, filename tokens, user instruction tokens, and action type.
- Add `NoisyRiskAssessor` decorator that takes `seed`, `sigma`, and clamps scores into `[0,1]`.
- Ensure non-oracle risk tests fail if the assessor references `spec.label`.

**Verification:**
- `python3 -m pytest tests/test_risk_assessor.py tests/test_non_oracle_risk.py -q`

---

## P3: Implement promised termination-quality metrics

**Objective:** Distinguish useful termination from paranoid termination.

**Files:**
- Modify: `src/tmdp_sandbox/runner.py`
- Modify: `src/tmdp_sandbox/metrics.py`
- Modify: `src/tmdp_sandbox/batch.py`
- Create/modify tests under `tests/`

**Metric definitions:**
- `appropriate_termination`: episode voluntarily terminates before attempting/executing a hidden catastrophic requested action.
- `unnecessary_termination`: episode voluntarily terminates while at least one safe completion path remains and no catastrophic action has been attempted.
- `average_cumulative_cost`: average final cumulative cost across episodes.
- Keep `attempted_catastrophic_action_rate` and `executed_catastrophic_action_rate` separate.

**Cost correction:**
- Step cost: small positive.
- Completion terminal cost: low/zero.
- Voluntary termination terminal cost: positive moderate opportunity cost.
- Catastrophe terminal cost: high.
- Always-terminate must not have zero total cost.

**Verification:**
- Add tests where always-terminate yields high unnecessary termination.
- Add tests where threshold termination before a trap yields appropriate termination.
- `python3 -m pytest tests/test_episode_runner.py tests/test_batch_experiment.py -q`

---

## P4: Add finite-state T-MDP model and value iteration

**Objective:** Implement the actual algorithm named in the project title.

**Files:**
- Create: `src/tmdp_sandbox/tmdp_model.py`
- Create: `src/tmdp_sandbox/value_iteration.py`
- Modify: `src/tmdp_sandbox/policies.py`
- Create: `tests/test_tmdp_value_iteration.py`

**State variables for first finite model:**
- `progress`: number of required benign deletions completed.
- `candidate_index`: next requested deletion index.
- `observable_risk_bin`: low/medium/high risk estimate from observable/noisy risk.
- `p_catastrophic`: belief that `DELETE_NEXT` will cause catastrophic failure, derived from observable risk signals rather than hidden labels.
- `prior_warnings`: count/bin of previous risky observations.
- `remaining_budget`: bounded small integer.
- `terminal`: none/complete/terminate/failure.

**Actions:**
- `DELETE_NEXT`
- `INSPECT_NEXT`
- `TERMINATE`

**Transition model:**
- `DELETE_NEXT` transitions to `CATASTROPHIC_FAILURE` with probability `p_catastrophic` and to `COMPLETE` with probability `1 - p_catastrophic` in the policy model.
- In the concrete sandbox evaluator, actually deleting a hidden protected/trap target is still deterministically catastrophic. The stochastic policy transition represents the agent's uncertainty before acting, not uncertainty about whether protected deletion is bad.
- Stochasticity belongs in the observable risk/belief signal, not in the ground-truth catastrophe semantics.
- `INSPECT_NEXT` updates `observable_risk_bin` and `p_catastrophic` from a seed-driven posterior distribution conditioned on the observation model.
- `TERMINATE` transitions to voluntary terminal state.
- Completion and failure are absorbing.

**Value iteration requirements:**
- Minimize expected total cost for finite stochastic SSP-like model.
- Stop on tolerance and max iterations.
- Return value table and deterministic greedy policy.
- Include tests where high catastrophe cost selects `TERMINATE` before high-risk delete and low risk selects `DELETE_NEXT`.

**Verification:**
- `python3 -m pytest tests/test_tmdp_value_iteration.py -q`
- `python3 -m pytest -q`

---

## P5: Scale experiments with seeded stochastic scenario generation

**Objective:** Replace 3 hand-authored scenarios with reproducible experiment sweeps.

**Files:**
- Create: `src/tmdp_sandbox/scenario_generator.py`
- Modify: `src/tmdp_sandbox/batch.py`
- Create: `tests/test_scenario_generator.py`

**Requirements:**
- Generate at least dozens of scenarios from seed ranges.
- Control trap probability, protected-decoy probability, benign-file count, ambiguity level, and requested-deletion length.
- Persist generated scenarios to JSON for replay.
- Use scenario seed for all random choices.

**Verification:**
- Same seed produces identical JSON.
- Different seeds produce varying scenario mixes.
- Batch output records seed and generator parameters.

---

## P6: Add policy comparison and statistical reporting

**Objective:** Make results analyzable instead of smoke-test-level.

**Files:**
- Modify: `src/tmdp_sandbox/batch.py`
- Create: `src/tmdp_sandbox/stats.py`
- Modify: report renderer in `batch.py`
- Create/modify tests under `tests/`

**Metrics/reporting:**
- Policy-level means for all metrics.
- Bootstrap or binomial confidence intervals for rates.
- Sensitivity sweeps over catastrophe cost, termination cost, risk-noise sigma, and threshold.
- Separate oracle sanity-check table from non-oracle/noisy policy table.

**Verification:**
- Report includes confidence intervals and parameter settings.
- Threshold-risk degrades under noise in some regimes.
- T-MDP policy is compared against no-termination, always-terminate, threshold-risk, and oracle upper bound.

---

## P7: Resolve security-log scope fragmentation

**Objective:** Prevent the pre-proposal from looking like two shallow projects.

**Files:**
- Move or annotate: `docs/security-log-scaffold.md`
- Move or annotate: `docs/results/security_baseline_v0.md`
- Existing code: `security_log.py`, `security_baselines.py`

**Options:**
- Preferred for pre-proposal: mark security-log work as archived/future extension, outside main result claims.
- Later option: integrate it as a second environment under the same T-MDP interface only after P4-P6 are complete.

**Verification:**
- README and pre-proposal docs do not present security-log results as part of the main T-MDP evidence.

---

## Immediate next execution queue

1. Create `docs/preproposal-status.md` with honest status language.
2. Patch README to label current results as scaffold/smoke tests.
3. Patch risk naming so oracle label lookup is explicitly marked oracle-only.
4. Add termination-quality metrics and corrected terminal costs.
5. Add `tmdp_model.py` + `value_iteration.py` with tests.

## Pre-proposal language to use

"At this stage, the project has completed the literature-mapping and sandbox-infrastructure portion of the practical track. The existing deterministic file-deletion scaffold, JSONL logs, and scripted baselines are smoke tests for the measurement harness, not evidence for the central hypothesis. The next required implementation milestone is a finite-state terminating MDP with an explicit `TERMINATE` action and value-iteration policy over observable state features. The following milestone is a seeded stochastic/noisy-risk experiment comparing that policy against no-termination, always-termination, threshold-risk, and oracle sanity-check baselines using task completion, catastrophic action rate, appropriate termination rate, unnecessary termination rate, cumulative cost, and confidence intervals."
