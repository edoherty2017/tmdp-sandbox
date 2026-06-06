# T-MDP Sandbox Anchor Plan

> For Hermes: Use this as the canonical project anchor. Keep execution ordered by priority only. No schedule estimates.

Goal: Build a controlled sandbox that tests whether a terminating Markov decision process (T-MDP) policy can reduce catastrophic AI-agent actions while preserving useful task completion.

Architecture: The project has three layers: (1) theoretical T-MDP formulation, (2) sandboxed task execution and logging, and (3) policy evaluation comparing no-termination, heuristic termination, and risk-sensitive optimal termination. The first testbed is controlled file deletion because it is easy to instrument, safety-critical, and directly maps to catastrophic tool-use behavior.

Tech stack anchor: Python, pytest, deterministic fixture directories, structured JSONL logs, optional LLM judge/risk assessor behind an interface, and analysis notebooks/scripts once data exists.

## Non-negotiable sequencing rules

1. Safety harness comes before any autonomous agent execution.
2. Logging/provenance comes before policy comparison.
3. A deterministic non-LLM baseline comes before LLM-judge risk scoring.
4. Synthetic file-deletion tasks come before external benchmark ingestion.
5. Every experiment must have a replayable config, seed, policy name, and outcome label.

## Repo ownership map

This private repo owns:
- Project proposal/source notes.
- Sandbox environment code.
- T-MDP formulation notes and simulation code.
- Evaluation scripts and experiment configs.
- Research notes and paper/dataset triage.

This repo does not own:
- Real credentials, live destructive commands, or unreviewed malware/cyber exploit artifacts.
- Public release materials until explicitly approved.

## P1: Repository and safety baseline

Deliverables:
- Private GitHub repo initialized from `D:/ML/tmdp-sandbox`.
- Original proposal preserved under `docs/source/`.
- Safety policy for file-deletion sandbox documented.
- Empty Python package/test scaffold committed.

Pass/fail gates:
- PASS if repo is private and pushed.
- PASS if no real user directories are included as sandbox targets.
- PASS if planned destructive operations are constrained to generated temp fixtures.

## P2: Formal problem formulation

Deliverables:
- Define T-MDP tuple: states, actions, transitions, costs/rewards, absorbing completion state, absorbing termination state.
- Define risk estimate variable and how it enters state/action selection.
- Define candidate objective criteria: expected cost, risk-sensitive cost, constrained failure probability, and stochastic-shortest-path framing.

Pass/fail gates:
- PASS if every variable used by the policy has an observable/loggable source.
- PASS if termination and task completion are disjoint absorbing outcomes.
- PASS if catastrophic failure is distinct from voluntary termination.

## P3: Deterministic file-deletion sandbox

Deliverables:
- Generate fixture directory trees with benign targets, protected decoys, and irreversible-action traps represented safely.
- Implement command/action abstraction; no raw shell deletion in early tests.
- Emit JSONL event logs for state, action, risk estimate, policy decision, and outcome.

Pass/fail gates:
- PASS if tests can prove protected files survive all baseline runs.
- PASS if every action is replayable from logs.
- PASS if sandbox cleanup cannot traverse outside its temp root.

## P4: Baseline policies

Deliverables:
- No-termination baseline.
- Threshold termination baseline.
- Oracle/synthetic-risk baseline for sanity checks.

Pass/fail gates:
- PASS if baseline metrics report task completion rate, termination rate, catastrophic failure rate, and average path cost.
- PASS if results are deterministic under fixed seeds.

## P5: Risk assessment module

Deliverables:
- Risk assessor interface.
- Deterministic heuristic assessor first.
- Optional LLM judge adapter second, with prompt/version logging.

Pass/fail gates:
- PASS if LLM judge can be disabled without changing experiment schema.
- PASS if judge output is stored with raw response, parsed score, and failure mode.

## P6: T-MDP policy computation

Deliverables:
- Simulation environment model.
- Value iteration / stochastic-shortest-path solver candidate.
- Risk-sensitive or constrained objective variant.

Pass/fail gates:
- PASS if policy can be computed on toy state spaces and compared against heuristic baselines.
- PASS if computed policy is exported in a replayable form.

## P7: Benchmark and dataset triage

Deliverables:
- SafeToolBench fit assessment.
- Risky-Bench fit assessment.
- BountyBench/securitydatasets fit assessment with safety restrictions.

Pass/fail gates:
- PASS if each candidate is labeled: usable now, needs adapter, out-of-scope, or unsafe/unavailable.
- PASS if dataset licenses/access constraints are recorded.

## P8: Evaluation and report artifacts

Deliverables:
- Experiment matrix.
- Plots/tables for failure-rate reduction vs task-completion tradeoff.
- Final report sections mapped to formulation, sandbox, policy, results, and limitations.

Pass/fail gates:
- PASS if results can be regenerated from committed configs and non-secret data.
- PASS if limitations distinguish sandbox artifacts from real-world agent safety claims.

## Immediate next execution queue

P1.1 Verify repo privacy and remote push.
P1.2 Add minimal package, pytest config, and a first test that asserts fixture cleanup stays under a temp root.
P2.1 Draft the formal T-MDP tuple in `docs/formulation.md`.
P3.1 Implement a fixture generator that creates benign/protected/trap file classes under a temporary root.
P4.1 Implement no-termination and threshold policies against synthetic risk traces.
