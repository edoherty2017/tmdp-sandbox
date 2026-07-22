# T-MDP Sandbox for Catastrophic Action Prevention

> [!IMPORTANT]
> ## 📣 TEAM: READ THIS FIRST — Implementation status (verified 2026-07-21)
>
> **Where we are:** All three pipeline phases are implemented and tested — Phase 1 builds baseline-integrity + sliding-window context features from Windows event logs, Phase 2 is a calibrated logistic regression producing P(malicious), and Phase 3 is the T-MDP with value iteration, which derives the block threshold **p\* = 0.40 analytically from declared costs** instead of hand-tuning. Sequential-block policy and DEFER are in. **118/118 tests passing** on a fresh clone; ~3.3k lines of source, 12 experiment scripts covering every result in the report.
>
> **Headline results:** Large independent eval (3,839 events, 15 held-out OTRF ZIPs, 10 ATT&CK techniques, labels locked before scoring): **precision 1.000 / recall 0.947 / F1 0.973**. In-distribution CV F1 0.998; calibration ECE 0.0003 (this is what makes the cost-derived 0.40 threshold valid). Sequential block raised benign allow rate **0.209 → 0.978 at zero safety cost**. The 15,000-episode policy comparison is done.
>
> **Milestones:** Proposal, M1, M2, and draft report ✅ complete. The **only open item is the final report, due Aug 9**. Known future-work items: cross-event context scoring for T1003.003 (worst technique, recall 0.663), labeling coverage for object-access EventIDs (4656/4658/4663), and a fully global T-MDP over the remaining event queue.
>
> **⚠️ Three things we need to decide together (implementation vs. latest proposal doc):**
> 1. The proposal specifies the risk judge as a rule-based scorer **combined with an LLM judge**; the implementation uses only the calibrated classifier, and the report defends dropping the LLM (LLM confidence scores aren't calibrated, and it would confound LLM quality with T-MDP quality). We either add an LLM-judge experiment or present the substitution as a deliberate design decision.
> 2. The tool-use/reasoning-agent leg (Risky-Bench / SafeToolBench) isn't implemented — everything is on the cybersecurity command-line leg.
> 3. The proposal names LangChain as the framework; the report argues against it. Same decision as #1.
>
> **To reproduce:** clone, `pip install -e '.[dev]'`, `pytest` (no data needed). Experiment scripts need the OTRF ZIPs in `data/raw/` — lists in `runs/train_classifier.py` and `runs/run_large_independent_eval.py`.

---

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
