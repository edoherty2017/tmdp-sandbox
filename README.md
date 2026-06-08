# T-MDP Sandbox for Catastrophic Action Prevention

CS5100 Summer 2026 project: "Cost-Calibrated Termination MDPs for Security Command Classification."

## Core idea

Model an AI agent's real-time command execution decisions as a Terminating Markov
Decision Process (T-MDP) with two absorbing endpoints:

- **EXECUTE**: the agent allows the command to run.
- **BLOCK**: the agent refuses before a malicious command causes harm.

The safety-utility tradeoff is controlled by declared costs, not a manually tuned threshold.
Value iteration derives the block threshold analytically:

```
p* = (c_block − c_execute) / c_compromise
```

With `c_block=5, c_execute=1, c_compromise=10` → `p* = 0.4000`.

## Three-phase pipeline

| Phase | Component | Purpose |
|---|---|---|
| 1 | `context_window.py` | Baseline integrity check + sliding-window event features |
| 2 | `classifier.py` | Calibrated logistic regression → P(malicious) |
| 3 | `tmdp_model.py` + `value_iteration.py` | T-MDP value iteration → EXECUTE / BLOCK / DEFER |

## Current status — Milestone 2 complete (2026-06-08)

**Classifier (Phase 2)**
- 5-fold CV: precision=1.000, recall=0.997±0.007, F1=0.998±0.003 (12,409 events: 11,791 benign + 618 malicious)
- Cross-technique generalization (2 held-out technique ZIPs): F1=0.921, precision=1.000
- Calibration: ECE=0.0003 in-distribution; near-binary output confirms T-MDP threshold p*=0.40 is operationally valid

**Large independent evaluation (authoritative generalization result)**
- 3,839 events across 15 held-out OTRF ZIPs, 10 MITRE ATT&CK techniques
- Labels committed to disk before any model scoring; single evaluation pass, no iteration
- **Precision=1.000, Recall=0.947, F1=0.973** (FP=0, FN=179)
- 5 of 9 countable techniques: recall=1.000; worst case: T1003.003 NTDS.dit recall=0.663 (context-window limitation)
- An earlier 30-event evaluation that reported F1=1.000 was retracted due to test-set contamination (see report §6.7.1)

**T-MDP (Phase 3)**
- Derives `p*=0.4000` from declared costs; validated by McNemar p=1.91e-6 in file-deletion domain
- Security batch: 15,000 episodes (500 scenarios × 5 noise levels × 6 policies)
- T-MDP always reduces malicious-execution rate vs threshold-0.5 in the correct direction

**Sequential block architecture**
- Replaces stop-on-first with per-event BLOCK_EVENT, continuing the episode
- Benign allow rate: 0.209 → 0.978 (+77 pp) at zero safety cost (Wilcoxon p=9.8×10⁻⁸⁴)

**Tests**: 118 passing

## Key documents

| Document | Purpose |
|---|---|
| `docs/cs5100-practical-report-draft.md` | Main report (Related Work, all M2 results, large eval, contamination retraction) |
| `docs/cs5100-proposal.md` | Course proposal (submitted 2026-06-21) |
| `docs/results/fair-comparison-writeup.md` | File-deletion domain validation (McNemar, cost sweep) |
| `docs/plans/2026-06-07-security-realignment-plan.md` | Domain pivot rationale and phase mapping |
| `docs/figures/` | Publication-quality figures (PNG) for the report |

## Key source files

| File | Role |
|---|---|
| `src/tmdp_sandbox/tmdp_model.py` | Domain-agnostic T-MDP model |
| `src/tmdp_sandbox/value_iteration.py` | Value iteration solver |
| `src/tmdp_sandbox/policies.py` | Policy adapters: T-MDP, threshold, sequential block, DEFER |
| `src/tmdp_sandbox/context_window.py` | Phase 1: baseline process lists + sliding-window features |
| `src/tmdp_sandbox/preprocessing.py` | OTRF data loading, `auto_label_event`, feature extraction |
| `src/tmdp_sandbox/classifier.py` | Phase 2: `MLCommandClassifier` (logistic + forest, calibrated) |
| `src/tmdp_sandbox/security_runner.py` | Security episode runner |
| `src/tmdp_sandbox/event_spec.py` | `EventSpec`, `SecurityScenario` types |
| `src/tmdp_sandbox/risk_noise.py` | Seeded noise model |

## Run scripts

| Script | What it does |
|---|---|
| `runs/train_classifier.py` | Train and save logistic + forest classifiers |
| `runs/run_security_batch.py` | Noise-sweep batch experiment (15,000 episodes) |
| `runs/run_security_cost_sweep.py` | Cost sensitivity sweep (c_compromise ∈ {10,50,100,500}) |
| `runs/run_cross_technique_eval.py` | Cross-technique generalization (2 held-out ZIPs) |
| `runs/run_calibration_eval.py` | ECE, MCE, Brier score measurement |
| `runs/run_sequential_eval.py` | Stop-on-first vs sequential block comparison |
| `runs/run_large_independent_eval.py` | Large independent evaluation (labels-first protocol) |
| `runs/generate_figures.py` | Generate all 5 publication figures → `docs/figures/` |

## Reproducing results

```bash
python3 -m pytest -q                           # 118 tests
python3 runs/train_classifier.py               # train classifier (needs data/raw/malicious/)
python3 runs/run_security_batch.py             # batch experiment → runs/security_batch/
python3 runs/run_large_independent_eval.py     # large eval → runs/large_independent_eval/
                                               # (needs data/raw/eval_holdout/ ZIPs)
python3 runs/generate_figures.py               # figures → docs/figures/*.png
```

## Datasets

Raw OTRF ZIPs are not committed (too large). Download from
[OTRF Security Datasets](https://github.com/OTRF/Security-Datasets):

- Training: place ZIPs in `data/raw/malicious/` (8 ZIPs listed in `runs/train_classifier.py`)
- Independent eval: place ZIPs in `data/raw/eval_holdout/` (15 ZIPs listed in `runs/run_large_independent_eval.py`)

`data/` and `models/` are gitignored. Trained models are regenerated by `runs/train_classifier.py`.

## Milestones

| Milestone | Due | Status |
|---|---|---|
| Proposal | 2026-06-21 | Done |
| M1: Three-phase pipeline + classifier | 2026-07-05 | Done |
| M2: DEFER, cost sweep, cross-technique, sequential, large eval | 2026-07-19 | Done |
| Draft report | 2026-08-02 | Done |
| Final report | 2026-08-09 | In progress |
