# Security Command Classification + T-MDP Decision Layer
## Project Realignment Plan — 2026-06-07

### The change in one sentence

Pivot the domain from a toy file-deletion sandbox to a real security event log problem.
The three-phase structure from the group chat maps directly onto the existing codebase
without rewriting the T-MDP machinery.

---

## Phase mapping

| Group chat phase | What it is | Existing code status |
|---|---|---|
| Phase 1: baseline integrity + context window | Prefilter using known-good command list; extract sliding-window features from event sequence | **New — must build** |
| Phase 2: classification (malicious / benign / uncertain) | scikit-learn classifier trained on labeled event logs → outputs P(malicious) | **New — must build** |
| Phase 3: decision making (block / allow / defer) | T-MDP value iteration over P(malicious) from Phase 2 | **Already implemented** |

---

## Domain mapping (what stays, what renames)

| File-deletion concept | Security concept | Code change |
|---|---|---|
| `FileSpec(path, label)` | `EventSpec(command, event_id, process, label)` | Rename + extend `scenario.py` |
| `SandboxScenario` (list of files) | `SecurityScenario` (sequence of events) | Rename + extend `scenario.py` |
| `DELETE path` | `EXECUTE command` (allow it) | Rename action strings in `actions.py`, `runner.py` |
| `TERMINATE` | `BLOCK command` (refuse) | Rename |
| `INSPECT_NEXT` | `DEFER` (request human review / more context) | Rename + **wire into runner** |
| `ObservableFeatureRiskAssessor` | `MLCommandClassifier` | Replace with trained model |
| `OracleLabelRiskAssessor` | Kept as oracle baseline for experiments | No change |
| `tmdp_model.py` | Unchanged — domain-agnostic | **Zero rewrite** |
| `value_iteration.py` | Unchanged | **Zero rewrite** |
| `risk_noise.py` | Unchanged | **Zero rewrite** |
| All 74 T-MDP tests | Kept as regression suite | **Zero rewrite** |

The T-MDP threshold formula stays the same:
`p* = (block_cost - execute_step_cost) / compromise_cost`

The only change is what the costs represent: `compromise_cost` is now the cost of
executing a malicious command (system compromise), not deleting a trap file.

---

## Datasets

| Source | Type | Use |
|---|---|---|
| securitydatasets.com — "Stopping Event Logging via MiniNt Registry Key" | Malicious Windows event logs | Training labels: malicious |
| github.com/sbousseaden/EVTX-ATTACK-SAMPLES — privesc_rotten_potato_from_webshell | Malicious privilege escalation events | Training labels: malicious |
| logpai/loghub Windows_2k.log | Benign Windows system logs | Training labels: benign |
| Synthetic generation (Vaibhav's note: "we can generate our own") | Supplemental benign + varied malicious | Augmentation if needed |

Vaibhav owns dataset acquisition. Raw files go in `data/raw/`. Processed files go in
`data/processed/`. Neither directory gets committed to git (add to `.gitignore`).

---

## New files to create

### `src/tmdp_sandbox/event_spec.py`
Replaces file-deletion `FileSpec`. Defines:
```python
@dataclass(frozen=True)
class EventSpec:
    command: str        # raw command string or event description
    event_id: int | None
    process_name: str | None
    user: str | None
    label: str          # "benign" | "malicious" — evaluator only, never given to classifier

@dataclass(frozen=True)
class SecurityScenario:
    scenario_id: str
    seed: int
    events: tuple[EventSpec, ...]
    requested_executions: tuple[int, ...]  # indices into events the agent must decide on
```

### `src/tmdp_sandbox/preprocessing.py`
- `load_evtx_attack_samples(path) -> list[EventSpec]` — parse EVTX XML or JSON exports
- `load_windows_2k_log(path) -> list[EventSpec]` — parse logpai format
- `extract_features(event, context_window) -> dict[str, float]` — Phase 1 + 2 features:
  - baseline integrity flag (is command in known-good whitelist?)
  - context window counts (how many high-entropy commands in last N events?)
  - command token features (TF-IDF or bag-of-words on command string)
  - event ID, process name one-hot or hash

### `src/tmdp_sandbox/classifier.py`
- `train_classifier(events, labels) -> ClassifierPipeline` — scikit-learn Pipeline:
  - ColumnTransformer: TF-IDF on command text + numeric features
  - LogisticRegression or RandomForestClassifier
  - Produces calibrated P(malicious) in [0, 1]
- `save_classifier(pipeline, path)` — joblib.dump
- `load_classifier(path) -> ClassifierPipeline` — joblib.load
- `MLCommandClassifier` — wraps trained pipeline, implements `DeleteRiskAssessor` protocol
  so it drops in wherever `ObservableFeatureRiskAssessor` is used today

### `src/tmdp_sandbox/context_window.py`
Phase 1 implementation:
- `BaselineIntegrityChecker` — whitelist of known-good command patterns (parsed from
  benign dataset); returns True if command matches baseline
- `ContextWindowFeatureExtractor(window_size=10)` — sliding window over event sequence,
  computes: entropy of recent commands, count of known-bad event IDs, process chain depth

---

## Files to modify

### `scenario.py`
- Keep `FileSpec` + `SandboxScenario` for backward compat with existing tests
- Add `EventSpec` + `SecurityScenario` alongside them
- Share `load_scenario_file` logic

### `risk.py`
- Add `MLCommandClassifier` class implementing `DeleteRiskAssessor` protocol
- Keep `ObservableFeatureRiskAssessor` (useful as a no-training-data fallback baseline)
- Keep `OracleLabelRiskAssessor` (oracle baseline for experiments)

### `runner.py`
- Wire `DEFER` (currently `INSPECT_NEXT`) into the execution loop
- A DEFER step: pauses execution, logs deferral, counts as a step cost
- This is the existing stated limitation — now we have real motivation to implement it

### `policies.py`
- Add `build_security_policy()` that runs Phase 1 → Phase 2 → Phase 3 in order:
  1. Check baseline integrity (Phase 1)
  2. Build context window features (Phase 1)
  3. Query `MLCommandClassifier` for P(malicious) (Phase 2)
  4. Pass P(malicious) to T-MDP value iteration (Phase 3)
  5. Emit EXECUTE / BLOCK / DEFER

### `batch.py`
- Add `SecurityBatchExperiment` alongside existing `run_batch_experiment`
- Accepts `SecurityScenario` list and `MLCommandClassifier`

---

## Milestone plan

### Proposal — 06/21 (2 weeks)
**Goal**: Formal problem statement with new domain. Team delivers:
- Updated problem formulation: security event execution as an MDP
- Dataset acquisition (Vaibhav): raw files downloaded and spot-checked
- Domain mapping document (Patrick): T-MDP formulation for security context
- `event_spec.py` skeleton (user): types defined, basic validation tests passing

### Milestone 1 — 07/05 (4 weeks)
**Goal**: Phase 1 + Phase 2 working. Classifier produces calibrated P(malicious).
- `preprocessing.py`: EVTX and logpai parsers complete, feature extraction working
- `context_window.py`: baseline integrity check + context window features
- `classifier.py`: scikit-learn pipeline trained, cross-validation accuracy reported
- Tests: `test_classifier.py`, `test_context_window.py`
- Deliverable: classifier produces P(malicious) ∈ [0, 1] for a held-out test set;
  precision/recall/AUC reported

### Milestone 2 — 07/19 (6 weeks)
**Goal**: Phase 3 integrated. Full pipeline end-to-end. Experiments run.
- `DEFER` wired into runner
- `build_security_policy()` complete: Phase 1 → Phase 2 → Phase 3 in one call
- Expanded batch experiment with security scenarios
- Primary comparison: scripted threshold (Phase 2 only) vs T-MDP (Phase 2 + Phase 3)
- Cost sweep: how does compromise_cost change the T-MDP operating point?
- Per-signal-quality breakdown: easy vs ambiguous attack samples
- 74 existing T-MDP tests still passing (regression)

### Draft report — 08/02
### Final report — 08/09

---

## Division of labor

| Person | Primary responsibility |
|---|---|
| Patrick | Theoretical formulation (T-MDP + SSP for security domain), background/related work section, report writing |
| Vaibhav | Dataset acquisition + preprocessing, feature engineering, Phase 2 classifier training |
| User | Context window (Phase 1), T-MDP integration (Phase 3), DEFER wiring, batch experiments, results |

---

## What does NOT change

The following are complete and correct and should not be touched:
- `tmdp_model.py` — belief-state T-MDP (domain-agnostic)
- `value_iteration.py` — standard VI
- `risk_noise.py` — seeded noise model
- `calibrated_inspection_observations()` — used for DEFER belief updates
- All 74 existing tests — kept as regression suite for the T-MDP layer
- The threshold formula `p* = (c_block - c_execute) / c_compromise`
- The McNemar paired significance test methodology
- The cost sensitivity sweep methodology

The existing results in `docs/results/fair-comparison-writeup.md` become the
**baseline/sanity-check appendix** for the final report: "in a controlled domain
with known ground truth, the T-MDP framework behaves as expected — threshold
derivation works, cost sensitivity is monotone."

---

## Key risk

The biggest risk is Phase 2 classifier quality. If the security datasets are too
small, too imbalanced, or too noisy, P(malicious) will be poorly calibrated and
the T-MDP Phase 3 results will be uninterpretable. Mitigation:

1. Check class balance before training (malicious vs benign event counts)
2. Use calibrated probability outputs (LogisticRegression with `class_weight='balanced'`,
   or isotonic/Platt calibration on top of RandomForest)
3. Fall back to synthetic generation if real datasets are insufficient
4. Report calibration curve (reliability diagram) in the paper — this is a legitimate
   scientific contribution, not a cop-out

If the classifier is poor, the honest result is still publishable: "Phase 3 T-MDP
cannot compensate for a low-quality Phase 2 signal" — which is exactly what the
ambiguity sweep already shows in the existing results.
