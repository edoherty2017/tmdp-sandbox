# T-MDP Sandbox — Cost-Calibrated Termination MDPs for Security Command Classification

**An offline research sandbox.** Every experiment in this repository replays recorded OTRF
Windows telemetry (Sysmon / Security event logs); BLOCK decisions are simulated. EID 4688
process-creation records are post-execution artifacts used as a proxy for the feature set a
pre-execution enforcement hook would observe — nothing here executes or prevents live commands.

> [!IMPORTANT]
> ## 📣 ANNOUNCEMENT (2026-07-22): review remediation complete — what was broken, what we fixed
>
> The 2026-07-21 adversarial review upheld **15 findings** against the draft
> (`docs/review/2026-07-21-adversarial-review-findings.md`). Every required fix is now applied,
> every experiment regenerated, and the report rewritten. Per-finding responses:
> `docs/review/2026-07-21-fix-response.md`.
>
> **What was broken:**
> 1. **Circular labels** — training labels were a deterministic function of the classifier's
>    own features, so CV F1 and the calibration story measured self-agreement, not skill.
> 2. **Mislabeled data** — 438/618 (70.9%) of "malicious" training events were VirtualBox
>    housekeeping polls; ~70% of eval "attacks" matched the bare substring `'wmi'` in routine
>    WmiPrvSE boilerplate.
> 3. **Rigged benign set** — eval label rules only ever called whitelist processes benign and
>    silently excluded ~98% of events, so precision=1.000 was guaranteed by construction; the
>    model agreed with a 21-process whitelist rule on every single event.
> 4. **Broken statistics** — McNemar p-values used a wrong formula (2-df tail for a 1-df test);
>    no CIs; a headline Wilcoxon p on a by-construction effect; the flagship eval scored every
>    event with an *empty* context window.
> 5. **Irreproducible** — unpinned library versions, no committed artifacts, and report tables
>    (McNemar b-column, DEFER count, calibration bins) that did not match the repo's own outputs.
> 6. **Oversold framing** — offline log replay presented as live "catastrophic action
>    prevention"; the T-MDP's planning cost was back-derived to hit p*=0.40.
>
> **What we fixed:**
> - **Labels**: source- and mask-aware EID-10 rule (requires `PROCESS_VM_READ` + non-agent
>   source; malicious training pool 618 → **144**); T1047 rule requires real WMI-exec tokens;
>   agent polls now labeled benign so model FPs are *counted*, not hidden.
> - **Eval harness**: real k=10 context windows; trivial baselines (whitelist rules,
>   always-malicious) reported side-by-side; Wilson + cluster-bootstrap CIs; exclusion funnel
>   disclosed; new hard-benign FP eval (152 hand-authored admin commands); new
>   threshold-0.5-sequential control arm.
> - **Statistics**: exact binomial McNemar with Holm correction; exact sign test replacing the
>   Wilcoxon; structural (subset-property) effects labeled as such, not tested as discoveries.
> - **Reproducibility**: exact library versions pinned in `pyproject.toml` and stamped into
>   every results JSON; small run artifacts committed; all tables regenerated from one artifact
>   vintage (Python 3.14.3, scikit-learn 1.9.0, numpy 2.5.1, pandas 3.0.3, joblib 1.5.3).
> - **Reporting**: report and README rewritten from the regenerated artifacts; every defect
>   above is disclosed in the report body and §7.5, in the same voice as the existing §6.7.1
>   retraction; framing rescoped to offline replay.
>
> **What the honest numbers look like (old draft → regenerated):**
>
> | Quantity | Old draft (pre-fix pipeline) | Regenerated (pinned env) |
> |---|---|---|
> | Training corpus | 12,409 events (618 malicious) | 11,935 events (**144** malicious) |
> | Large independent eval P / R / F1 | 1.000 / 0.947 / 0.973 (FP=0) | **0.1046 / 0.955 / 0.1886 (FP=7,077)** |
> | Model vs 21-process whitelist rule | (not measured) | **100% agreement (8,410/8,410)** |
> | 5-fold CV F1 | 0.998±0.003 | 1.000±0.000 (circular labels — see caveat below) |
> | Cross-technique F1 | 0.921 ("honest generalization gap") | 1.000 (diagnostic only — tune-on-test) |
> | Security McNemar b per σ | 6/6/3/2/4, approx χ² | **0/0/0/0/3, exact p, all Holm-adjusted p=1.0** |
> | Sequential-block statistic | Wilcoxon W=124,251, p=9.8e-84 | exact sign test +498/0/−0 (structural — descriptive, not inferential) |
> | Hard-benign FP rate | (eval did not exist) | **152/152 = 100% at p\*=0.40** |
> | File-deletion McNemar (σ=0.15) | b=20, c=0, p=1.91e-6 | **unchanged: b=20, c=0, p=1.907e-6** |
>
> **What survives:** the T-MDP architectural contribution (cost-derived p\*=0.40, the DEFER
> value-of-information band, the sequential-block architecture) and the file-deletion-domain
> significance result, which is classifier-independent. **What does not:** on the independent
> eval the security classifier is behaviorally indistinguishable from a 21-process whitelist
> rule (100% agreement), and its F1 (0.1886) is below the trivial 3-process whitelist baseline
> (0.1956). The old headline numbers are retracted, not softened.
>
> **Milestones:** Proposal, M1, M2, and draft report complete. The **only open deliverable is
> the final report, due Aug 9** — now rewritten from the regenerated artifacts; needs a full
> team read-through.
>
> **⚠️ Three things we still need to decide together** (unchanged by the review — still open).
> For items 1 and 3, the proposal-of-record is **`SandBox Project.docx`** (repo root; extracted
> text at `docs/source/SandBox_Project_extracted.md`, whose line 43 specifies a risk module that
> "features an LLM judge as the simplest instance", and which names LangChain) — not
> `docs/cs5100-proposal.md`:
> 1. That proposal specifies the risk judge as a rule-based scorer **combined with an LLM
>    judge**; the implementation uses only the calibrated classifier, and the report defends
>    dropping the LLM. We either add an LLM-judge experiment or present the substitution as a
>    deliberate design decision.
> 2. The tool-use/reasoning-agent leg (Risky-Bench / SafeToolBench) isn't implemented —
>    everything is on the cybersecurity command-line leg.
> 3. That proposal names LangChain as the framework; the report argues against it. Same
>    decision as #1.
>
> **To reproduce:** clone, install the pinned environment (`pip install -e '.[dev]'` —
> `pyproject.toml` pins exact versions), `pytest` (**118/118 tests passing**, no data needed;
> verified by the review on a fresh clone). Experiment scripts need the OTRF ZIPs in
> `data/raw/` — lists in `runs/train_classifier.py` and `runs/run_large_independent_eval.py`.

---

CS5100 Summer 2026 project: "Cost-Calibrated Termination MDPs for Security Command Classification."

## Core idea

Model a command-execution gate as a Terminating Markov Decision Process (T-MDP) with two
absorbing endpoints:

- **EXECUTE**: the policy allows the command.
- **BLOCK**: the policy refuses it.

The safety-utility tradeoff is controlled by declared costs, not a manually tuned threshold.
Value iteration derives the block threshold analytically:

```
p* = (c_block − c_execute) / c_compromise
```

With `c_block=5, c_execute=1, c_compromise=10` → `p* = 0.4000`.

All evaluation is offline replay of recorded telemetry: the policy scores captured events in
recorded order and its BLOCK decisions are simulated, never enforced.

## Three-phase pipeline

| Phase | Component | Purpose |
|---|---|---|
| 1 | `context_window.py` | Baseline integrity check + sliding-window event features |
| 2 | `classifier.py` | Calibrated logistic regression → P(malicious) |
| 3 | `tmdp_model.py` + `value_iteration.py` | T-MDP value iteration → EXECUTE / BLOCK / DEFER |

## Current results — regenerated 2026-07-21 (post-review, pinned environment)

All numbers below are from the regenerated artifacts under `runs/` and
`data/processed/train_stats.json`. Old-draft numbers appear only in the banner table above,
attributed to the pre-fix pipeline.

**Classifier (Phase 2)**
- Corpus: 11,935 events — 11,791 benign / 144 malicious (≈1.2% prevalence) after the
  source/mask-aware EID-10 label fix.
- 5-fold CV: precision=1.000±0.000, recall=1.000±0.000, F1=1.000±0.000. **Circularity caveat:**
  the labels are a deterministic function of the same feature dictionary the classifier reads,
  so CV measures self-agreement with the auto-labeling rule, not detection skill. The perfect
  score on the corrected corpus makes this caveat more acute, not less.
- Cross-technique eval (2 held-out technique ZIPs, n=1,484, 90 malicious): F1=1.000.
  **Diagnostic only** — earlier feature and label iterations were tuned against these same
  ZIPs (tune-on-test), so this is not an honest generalization estimate.
- Calibration: ECE=0.0000, Brier=0.0000 — but degenerate. The model's output is fully binary
  (zero events score in (0.1, 0.9); 8 of 10 reliability bins are empty in both eval sets), so
  ECE cannot validate the p\*=0.40 threshold: there is no data anywhere near 0.4. Claims about
  model behavior are routed through the independent evaluation below, not through ECE.

**Large independent evaluation (held-out-ZIP replay within the same lab environment)**
- 8,410 labeled events across 15 held-out OTRF ZIPs, 12 MITRE ATT&CK techniques; 866 malicious
  / 7,544 benign (≈10.3% malicious prevalence). Labels committed to disk before scoring;
  single pass; events scored with real k=10 context windows (the pre-fix eval's empty-context
  defect is corrected).
- **Selection effect:** the labeling rules keep 8,410 of 230,676 raw events — a **96.35%
  exclusion rate**. The eval measures recall on rule-labeled attack events, not on the raw
  stream.
- **Precision=0.1046, Recall=0.955, F1=0.1886** (TP=827, FP=7,077, FN=39, TN=467). Recall
  Wilson 95% CI [0.939, 0.967]; precision Wilson 95% CI [0.098, 0.112]; F1 cluster-bootstrap
  95% CI [0.094, 0.989] — nearly vacuous with only 15 ZIP clusters.
- **Whitelist-baseline context:** the model agrees with a 21-process whitelist rule on
  8,410/8,410 events (**100%**), and a trivial 3-process whitelist beats it (F1 0.1956 vs
  0.1886; always-malicious scores 0.1867). On this eval the model is behaviorally a whitelist.
- The FP flood is concentrated in T1003.003 (7,032 FP; precision 0.0414) and T1047 (42/42
  benign flagged). Deduplicated by unique command line: P=0.9267 / R=0.962 / F1=0.944 —
  repeated command lines dominate the flood.
- **Single-lab scope:** the review found 14 of the 15 eval ZIPs share the training captures'
  lab environment/operator; nothing here estimates performance outside that lab.
- The pre-fix headline (precision 1.000 / recall 0.947 / F1 0.973) is retracted — it rested on
  empty-context scoring and mislabeled T1047/credential-access ground truth. An earlier
  30-event evaluation reporting F1=1.000 was already retracted for test-set contamination
  (report §6.7.1).

**Hard-benign evaluation (new, `runs/hard_benign_eval/`)**
- 152 hand-authored benign Windows-admin events (34 distinct processes, all outside the
  21-entry whitelist): **152/152 = 100% false positives at p\*=0.40** in both context modes;
  142/152 (93.4%) at p\*=0.50 with a self-consistent context stream. The model never says
  benign for any non-whitelist process at the deployed threshold.
- Caveat: the corpus is hand-authored, not captured telemetry — it does not estimate a
  deployment FP rate; it shows the model cannot clear non-whitelist admin activity at all.

**T-MDP (Phase 3)**
- Derives `p*=0.4000` from declared costs; security batch: 15,000 episodes
  (500 scenarios × 5 noise levels × 6 policies).
- **Tie-aware McNemar statement:** under matched noise the T-MDP's executed set is a subset of
  threshold-0.5's, so it can never be worse (c=0 is structural). At σ ≤ 0.15 the two policies
  are *identical* (b=0, zero discordant pairs); at σ=0.20, b=3 vs c=0 (exact p=0.25,
  Holm-adjusted p=1.0). **No security-domain McNemar row is significant.** The T-MDP arm has
  malicious-execution rate 0.000 at every σ; threshold-0.5 rises to 0.006 at σ=0.20.
- DEFER activity: 170/15,000 episodes (1.13%) contain at least one DEFER (241 DEFER events,
  all in the tmdp-p0.40 arm).
- **File-deletion domain (classifier-independent — the surviving significance evidence):** at
  σ=0.15 the T-MDP avoids catastrophe in 20 paired scenarios that the observable-threshold
  policy loses, with zero reversals (b=20, c=0, exact p=1.907e-6; recomputed from the
  regenerated episode logs in `runs/fair_batch/`).

**Sequential block architecture**
- Replaces stop-on-first with per-event BLOCK_EVENT, continuing the episode. Benign allow rate
  0.2091 → 0.9782 for the T-MDP arm at zero malicious executions; exact sign test +498/0/−0
  (p=1.2e-150), but the gain is **structural** — stop-on-first forfeits every event after its
  first block — so the test is descriptive, not inferential.
- New threshold-0.5-sequential control arm: benign allow 1.000 but 1 malicious execution in
  498 episodes (mal-exec 0.002, vs 0.000 for tmdp-sequential). The architectural gain is
  decision-layer-agnostic; the T-MDP's contribution is keeping mal-exec at zero.

**Tests**: 118 passing

## Key documents

| Document | Purpose |
|---|---|
| `docs/cs5100-practical-report-draft.md` | Main report (rewritten 2026-07-21 from the regenerated artifacts) |
| `docs/review/2026-07-21-adversarial-review-findings.md` | Adversarial review — the 15 upheld findings (F1–F15) |
| `docs/review/2026-07-21-fix-plan.md` | Consolidated fix/edit spec responding to the review |
| `docs/review/2026-07-21-fix-response.md` | Per-finding written responses (F1–F15): what was fixed, rebutted, and still open |
| `SandBox Project.docx` (repo root; also `docs/source/`) | Original team proposal — proposal-of-record for the LLM-judge / LangChain decision items |
| `docs/cs5100-proposal.md` | Course proposal (submitted 2026-06-21, post-pivot) |
| `docs/results/fair-comparison-writeup.md` | File-deletion domain validation (McNemar, cost sweep) |
| `docs/plans/2026-06-07-security-realignment-plan.md` | Domain pivot rationale and phase mapping |
| `docs/figures/` | Report figures (PNG), regenerated 2026-07-21 |

## Key source files

| File | Role |
|---|---|
| `src/tmdp_sandbox/tmdp_model.py` | Domain-agnostic T-MDP model |
| `src/tmdp_sandbox/value_iteration.py` | Value iteration solver |
| `src/tmdp_sandbox/policies.py` | Policy adapters: T-MDP, threshold, sequential block, DEFER |
| `src/tmdp_sandbox/context_window.py` | Phase 1: baseline process lists + sliding-window features |
| `src/tmdp_sandbox/preprocessing.py` | OTRF data loading, `auto_label_event` (source/mask-aware EID-10 rule), feature extraction |
| `src/tmdp_sandbox/classifier.py` | Phase 2: `MLCommandClassifier` (logistic + forest, calibrated) |
| `src/tmdp_sandbox/security_runner.py` | Security episode runner |
| `src/tmdp_sandbox/event_spec.py` | `EventSpec`, `SecurityScenario` types |
| `src/tmdp_sandbox/risk_noise.py` | Seeded noise model |

## Run scripts

| Script | What it does |
|---|---|
| `runs/train_classifier.py` | Train and save logistic + forest classifiers |
| `runs/run_security_batch.py` | Noise-sweep batch experiment (15,000 episodes) + exact McNemar |
| `runs/run_security_cost_sweep.py` | Cost sensitivity sweep (c_compromise ∈ {10,50,100,500}) |
| `runs/run_cross_technique_eval.py` | Cross-technique eval (2 held-out ZIPs; diagnostic) |
| `runs/run_calibration_eval.py` | ECE, MCE, Brier score measurement |
| `runs/run_sequential_eval.py` | Stop-on-first vs sequential block (incl. threshold-0.5-sequential arm) |
| `runs/run_large_independent_eval.py` | Large independent evaluation (labels-first protocol, real k=10 context) |
| `runs/run_fair_batch.py` | File-deletion domain fair comparison (paired episodes) |
| `runs/run_hard_benign_eval.py` | Hard-benign FP eval (152 hand-authored admin events) |
| `runs/generate_figures.py` | Generate all 5 publication figures → `docs/figures/` |

## Reproducing results

All results were produced in the pinned environment (Python 3.14.3, scikit-learn 1.9.0,
numpy 2.5.1, pandas 3.0.3, joblib 1.5.3 — pinned in `pyproject.toml`); borderline-count
metrics (McNemar b, DEFER counts) are not stable across library versions.

```bash
python3 -m pytest -q                           # 118 tests
python3 runs/train_classifier.py               # train classifier (needs data/raw/malicious/)
python3 runs/run_security_batch.py             # batch experiment → runs/security_batch/
python3 runs/run_large_independent_eval.py     # large eval → runs/large_independent_eval/
                                               # (needs data/raw/eval_holdout/ ZIPs)
python3 runs/run_hard_benign_eval.py           # hard-benign FP eval → runs/hard_benign_eval/
python3 runs/generate_figures.py               # figures → docs/figures/*.png
```

## Datasets

Raw OTRF ZIPs are not committed (too large). Download from
[OTRF Security Datasets](https://github.com/OTRF/Security-Datasets):

- Training: place ZIPs in `data/raw/malicious/` (8 ZIPs listed in `runs/train_classifier.py`)
- Independent eval: place ZIPs in `data/raw/eval_holdout/` (15 ZIPs listed in `runs/run_large_independent_eval.py`)

Raw `data/` and trained `models/` are gitignored; small run artifacts (`results.json`,
`summary.txt`, `mcnemar.json`) and `data/processed/train_stats.json` are committed so every
report number is auditable. Trained models are regenerated by `runs/train_classifier.py`.

## Milestones

| Milestone | Due | Status |
|---|---|---|
| Proposal | 2026-06-21 | Done |
| M1: Three-phase pipeline + classifier | 2026-07-05 | Done |
| M2: DEFER, cost sweep, cross-technique, sequential, large eval | 2026-07-19 | Done |
| Draft report | 2026-08-02 | Done (adversarially reviewed 2026-07-21; rewritten from regenerated artifacts) |
| Final report | 2026-08-09 | In progress |
