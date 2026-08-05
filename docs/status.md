# Project Status & Full Results (detailed)

This is the detailed status the README used to carry inline. The README is now a short
overview; everything complex lives here. Report source of truth is the Google Doc.

## Review remediation history (2026-07-21 → 22)

## 📣 ANNOUNCEMENT (2026-07-22): review remediation complete — what was broken, what we fixed

The 2026-07-21 adversarial review upheld **15 findings** against the draft
(`docs/review/2026-07-21-adversarial-review-findings.md`). Every required fix is now applied,
every experiment regenerated, and the report rewritten. Per-finding responses:
`docs/review/2026-07-21-fix-response.md`.

**What was broken:**
1. **Circular labels** — training labels were a deterministic function of the classifier's
   own features, so CV F1 and the calibration story measured self-agreement, not skill.
2. **Mislabeled data** — 438/618 (70.9%) of "malicious" training events were VirtualBox
   housekeeping polls; ~70% of eval "attacks" matched the bare substring `'wmi'` in routine
   WmiPrvSE boilerplate.
3. **Rigged benign set** — eval label rules only ever called whitelist processes benign and
   silently excluded ~98% of events, so precision=1.000 was guaranteed by construction; the
   model agreed with a 21-process whitelist rule on every single event.
4. **Broken statistics** — McNemar p-values used a wrong formula (2-df tail for a 1-df test);
   no CIs; a headline Wilcoxon p on a by-construction effect; the flagship eval scored every
   event with an *empty* context window.
5. **Irreproducible** — unpinned library versions, no committed artifacts, and report tables
   (McNemar b-column, DEFER count, calibration bins) that did not match the repo's own outputs.
6. **Oversold framing** — offline log replay presented as live "catastrophic action
   prevention"; the T-MDP's planning cost was back-derived to hit p*=0.40.

**What we fixed:**
- **Labels**: source- and mask-aware EID-10 rule (requires `PROCESS_VM_READ` + non-agent
  source; malicious training pool 618 → **144**); T1047 rule requires real WMI-exec tokens;
  agent polls now labeled benign so model FPs are *counted*, not hidden.
- **Eval harness**: real k=10 context windows; trivial baselines (whitelist rules,
  always-malicious) reported side-by-side; Wilson + cluster-bootstrap CIs; exclusion funnel
  disclosed; new hard-benign FP eval (152 hand-authored admin commands); new
  threshold-0.5-sequential control arm.
- **Statistics**: exact binomial McNemar with Holm correction; exact sign test replacing the
  Wilcoxon; structural (subset-property) effects labeled as such, not tested as discoveries.
- **Reproducibility**: exact library versions pinned in `pyproject.toml` and stamped into
  every results JSON; small run artifacts committed; all tables regenerated from one artifact
  vintage (Python 3.14.3, scikit-learn 1.9.0, numpy 2.5.1, pandas 3.0.3, joblib 1.5.3).
- **Reporting**: report and README rewritten from the regenerated artifacts; every defect
  above is disclosed in the report body and §7.5, in the same voice as the existing §6.7.1
  retraction; framing rescoped to offline replay.

**What the honest numbers look like (old draft → regenerated):**

| Quantity | Old draft (pre-fix pipeline) | Regenerated (pinned env) |
|---|---|---|
| Training corpus | 12,409 events (618 malicious) | 11,935 events (**144** malicious) |
| Large independent eval P / R / F1 | 1.000 / 0.947 / 0.973 (FP=0) | **0.1046 / 0.955 / 0.1886 (FP=7,077)** |
| Model vs 21-process whitelist rule | (not measured) | **100% agreement (8,410/8,410)** |
| 5-fold CV F1 | 0.998±0.003 | 1.000±0.000 (circular labels — see caveat below) |
| Cross-technique F1 | 0.921 ("honest generalization gap") | 1.000 (diagnostic only — tune-on-test) |
| Security McNemar b per σ | 6/6/3/2/4, approx χ² | **0/0/0/0/3, exact p, all Holm-adjusted p=1.0** |
| Sequential-block statistic | Wilcoxon W=124,251, p=9.8e-84 | exact sign test +498/0/−0 (structural — descriptive, not inferential) |
| Hard-benign FP rate | (eval did not exist) | **152/152 = 100% at p\*=0.40** |
| File-deletion McNemar (σ=0.15) | b=20, c=0, p=1.91e-6 | **unchanged: b=20, c=0, p=1.907e-6** |

**What survives:** the T-MDP architectural contribution (cost-derived p\*=0.40, the DEFER
value-of-information band, the sequential-block architecture) and the file-deletion-domain
significance result, which is classifier-independent. **What does not:** on the independent
eval the security classifier is behaviorally indistinguishable from a 21-process whitelist
rule (100% agreement), and its F1 (0.1886) is below the trivial 3-process whitelist baseline
(0.1956). The old headline numbers are retracted, not softened.

**Milestones:** Proposal, M1, M2, and draft report complete. The **only open deliverable is
the final report, due Aug 9** — now rewritten from the regenerated artifacts; needs a full
team read-through.

**Added 2026-07-22 (same day, after the remediation):** two new measured experiments close the
proposal-of-record gaps — LLM-judge calibration (`runs/llm_judge_calibration/`) and a
LangChain tool-use agent leg (`runs/tooluse_eval/`); results below and in "Current results".

**⚠️ The three proposal-gap items** — items 1 and 3 are now **built and measured**; what is
left to decide together is *presentation in the report*, not construction. The
proposal-of-record is **`SandBox Project.docx`** (repo root; extracted
text at `docs/source/SandBox_Project_extracted.md`, whose line 43 specifies a risk module that
"features an LLM judge as the simplest instance", and which names LangChain) — not
`docs/cs5100-proposal.md`:
1. **LLM judge — built and measured** (`runs/llm_judge_calibration/`). The measurement
   *reverses* §4.5's asserted rationale ("LLM confidence numbers are not calibrated"): on
   every non-circular subset the LLM judge is **better** calibrated than the deployed
   classifier (matched overall ECE 0.0663 vs 0.3447; hard-benign FP at p\*=0.40: 5.3% vs
   100%). §4.5 must be rewritten, not defended — the honest remaining grounds for the
   classifier-only deployment are operational (per-event latency/cost, sampling
   nondeterminism, a 0.55% refusal/parse-failure rate, model-snapshot dependence), not
   calibration. Open decision: how to present the revision.
2. **Tool-use agent leg — now exists as a sandboxed LangChain demo** (`runs/tooluse_eval/`):
   the proposal's full gate pipeline (rule scorer + LLM judge → T-MDP p\*=0.40 →
   PROCEED/STOP/DEFER) on 40 hand-authored SafeToolBench-*style* scenarios plus 5 live agent
   transcripts; combined scorer executes 0/20 risky and blocks 0/20 safe (rule-only: 4
   missed, 3 over-blocked). What remains vs the real benchmarks: no verbatim
   Risky-Bench/SafeToolBench items (scenario text is our own; only the SafeToolBench
   abstract/figure was reachable at run time), n=40, and the agent-demo pending actions are
   seeded (the CLI planner refuses risky plans upstream) — a demonstration on a constructed
   suite, not a benchmark result.
3. **LangChain — built and measured**: the tool-use leg runs on LangChain (langchain 1.3.14 /
   langchain-core 1.5.0, pinned in `pyproject.toml` `[llm]` extra) with a custom chat model
   over the claude CLI and an explicit message/tool loop keeping the gate between "model
   proposes" and "tool runs". Same open decision as #1: presentation, not construction.

**To reproduce:** clone, install the pinned environment (`pip install -e '.[dev]'` —
`pyproject.toml` pins exact versions), `pytest` (**162 tests**, no data needed — the previous
118 were verified by the review on a fresh clone; 44 tests added 2026-07-22: 13 LLM-judge,
20 tool-use, 11 labeling-rule). Experiment scripts need the OTRF ZIPs in
`data/raw/` — lists in `runs/train_classifier.py` and `runs/run_large_independent_eval.py`.
The two LLM experiments additionally need an authenticated `claude` CLI (see "Reproducing
results").

## Current results — regenerated 2026-07-21 (post-review, pinned environment)

All numbers below are from the regenerated artifacts under `runs/` and
`data/processed/train_stats.json`. Old-draft numbers appear only in the banner table above,
attributed to the pre-fix pipeline. The LLM-judge calibration and tool-use blocks were added
2026-07-22 from that day's run artifacts.

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

**LLM-judge calibration (new 2026-07-22, `runs/llm_judge_calibration/`)**
- `claude-opus-4-8` via the claude CLI (2.1.217) scored 542 events with real k=10 context
  windows — 240 train-pool (120 malicious / 120 benign, `auto_label_event` labels), 152
  hard-benign, 150 stratified eval-holdout — head-to-head against the deployed classifier
  under the same 10-bin reliability scheme as `run_calibration_eval.py`. This converts §4.5's
  asserted justification ("LLM confidence numbers are not calibrated") into a measured result.
- **The assertion is reversed by measurement.** Strict matched head-to-head (n=539; the 3 LLM
  refusals/unparseables excluded, never fabricated): overall ECE 0.0663 vs 0.3447 and Brier
  0.1101 vs 0.2884 in the judge's favor; hard-benign ECE 0.1282 vs 0.9203; eval-holdout ECE
  0.0790 vs 0.3498. The classifier "wins" only on train_pool (ECE 0.0005 vs 0.1993) — the one
  subset whose labels are circular for the classifier, where its score histogram is a
  degenerate 0/1 spike (120 / 0×8 / 120); that row is not evidence of classifier calibration.
- Hard-benign FP at p\*=0.40: judge 8/151 = 5.3% (Wilson 95% CI 2.7–10.1%) vs classifier
  152/152 = 100%; at 0.50: 1/151 = 0.7% vs 142/152 = 93.4%. No hard-benign event received an
  LLM score ≥ 0.6. (Hand-authored set — not a deployment FP-rate estimate.)
- Graded scores: the judge places 169/539 (31.4%) of events in the (0.1–0.9) desert, spread
  across all eight middle bins with actual rates rising near-monotonically with predicted
  score; the classifier's nominally similar 31.7% is mostly a single uninformative spike at
  [0.4–0.5) (140 events, actual rate 0.0286).
- Caveats: single-pass scoring, one model snapshot on one date; the judge's weakest region is
  the low-score train_pool bins ([0.1–0.2): predicted 0.1200 vs actual 0.6176 — judge misses
  or `auto_label_event` label noise, unresolvable from this artifact); 3/542 (0.55%)
  refusals/parse failures, all on benign events. Consequence for §4.5: the case for excluding
  the LLM judge cannot rest on calibration — the honest remaining grounds are operational
  (per-event latency/cost at telemetry rates, sampling nondeterminism, a refusal fallback
  path, model-snapshot dependence).

**Tool-use agent leg (new 2026-07-22, `runs/tooluse_eval/`)**
- LangChain agent (langchain 1.3.14 / langchain-core 1.5.0; custom chat model over the claude
  CLI; sandboxed mock tools, no real side effects) with the proposal's full gate pipeline:
  rule-based scorer + LLM judge (combined = 0.4·rule + 0.6·llm) → existing T-MDP value
  iteration (p\*=0.40) → PROCEED / STOP / DEFER.
- Gate eval on 40 hand-authored SafeToolBench-style scenarios (20 risky / 20 safe; unseeded):
  the combined scorer at T-MDP p\*=0.40 executes **0/20 risky and blocks 0/20 safe** (Wilson
  95% CI 0–16.1% each side); rule-only executes 4/20 risky and blocks 3/20 safe — in all 7
  rule-only failures the LLM judge scored correctly and the combined score rescued the
  decision. Judge calibration on scenario ground truth: ECE 0.0492, Brier 0.0044 (n=40, seven
  empty middle bins — indicative only).
- **No T-MDP-beats-threshold claim on this suite:** scenario scores are bimodal, so tmdp-p0.40
  and threshold-0.5 make identical gate decisions under every scorer. T-MDP-specific behavior
  appears only in the defer variant (3 safe DEFERs, 0 risky, combined scorer) and in the
  value-iteration provenance of p\*.
- 5 live end-to-end agent transcripts with the gate live: 2/2 risky STOPped (incl. EXFIL-1,
  which the rule scorer alone would pass at 0.05) and 3/3 safe PROCEEDed (incl. DEL-L1, which
  the rule scorer alone would block at 0.85); all five ended in a final answer.
- Caveats: authored scenarios, not deployment traffic and not verbatim SafeToolBench items
  (only the paper's abstract/figure was reachable at run time; style reference: Xia et al.,
  Findings of EMNLP 2025; the corpus was later released — see the verbatim-item eval below) —
  rates characterize the gate on this constructed set only. The
  demo's pending actions are **seeded**: the CLI planner by design refuses to volunteer risky
  tool-call plans (itself a valid first line of defense), so the harness supplies each
  scenario's canonical action; the gate decisions, scores, and the model's follow-up reactions
  are real, and the 40-scenario gate eval is unseeded.

**SafeToolBench verbatim-item eval (new 2026-08-03, `runs/safetoolbench_eval/`)**
- The SafeToolBench corpus (BITHLP/SafeToolBench @ `ffdef6e782b0`) became publicly reachable
  after the July run, so the existing gate (rule scorer + Claude judge + T-MDP at p\*=0.40)
  was run on all **1,000 verbatim items**. Each item ships its proposed API call(s), so the
  gate scores exactly the benchmark's pending calls with no planner step; an item is flagged
  if any call is STOPped.
- Rule-only flags **2.8%** (28/1000). Combined 0.4·rule + 0.6·llm flags **9.0%** (18/200,
  seeded stratified sample; zero LLM null responses; median judge score 0.02).
- **Not comparable to published SafeToolBench scores:** every released item is risky-labeled
  under a prospective-risk rubric that measures risk *awareness*; our metric is a
  catastrophe-cost *block* decision, and most items are ordinary-looking requests with latent
  risk that a calibrated judge scores far below a catastrophe threshold.
- **Cost dial demonstrated on real benchmark data:** raising c_compromise 10 → 50 → 100
  (p\* 0.40 → 0.08 → 0.04) moves the combined flag rate **9.0% → 23.0% → 40.0%**, while
  rule-only jumps from 2.8% straight to 100% once p\* falls below the 0.05 rule base score —
  the combined score is tunable; the rule score is not.

**Tests**: 162 passing


---

## Full run scripts & reproduction (moved from README)

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
| `runs/run_llm_judge_calibration.py` | LLM-judge vs classifier calibration head-to-head (542 events; requires authenticated `claude` CLI) |
| `runs/run_tooluse_eval.py` | Tool-use leg: 40-scenario gate eval + 5 LangChain agent demos (requires authenticated `claude` CLI) |
| `runs/run_safetoolbench_eval.py` | Verbatim SafeToolBench gate eval (1,000 items + cost dial; requires authenticated `claude` CLI for the combined arm) |
| `runs/generate_figures.py` | Generate all 5 publication figures → `docs/figures/` |

The two LLM scripts shell out to the local `claude` CLI (`claude-opus-4-8`; no API key). Model
responses are cached in each run directory (`responses.jsonl`, keyed by sha256 of
model+prompt; the calibration run also stores the exact prompts in `prompts.jsonl`), so reruns
replay identical prompts from cache without new model calls and interrupted runs resume.

## Reproducing results

All results were produced in the pinned environment (Python 3.14.3, scikit-learn 1.9.0,
numpy 2.5.1, pandas 3.0.3, joblib 1.5.3 — pinned in `pyproject.toml`); borderline-count
metrics (McNemar b, DEFER counts) are not stable across library versions. The tool-use leg
additionally pins langchain-core 1.5.0 / langchain 1.3.14 (`pip install -e '.[llm]'`).

The two LLM experiments require an **authenticated `claude` CLI** on PATH (results were
produced with CLI 2.1.217, model `claude-opus-4-8`, on 2026-07-22). With the response caches
in the run directories, reruns of identical prompts replay from cache; fresh scoring of new
prompts is a different model snapshot and may differ. Both scripts take `--limit N` for a
small smoke run.

```bash
python3 -m pytest -q                           # 162 tests
python3 runs/train_classifier.py               # train classifier (needs data/raw/malicious/)
python3 runs/run_security_batch.py             # batch experiment → runs/security_batch/
python3 runs/run_large_independent_eval.py     # large eval → runs/large_independent_eval/
                                               # (needs data/raw/eval_holdout/ ZIPs)
python3 runs/run_hard_benign_eval.py           # hard-benign FP eval → runs/hard_benign_eval/
python3 runs/run_llm_judge_calibration.py      # LLM-judge calibration → runs/llm_judge_calibration/
                                               # (claude CLI + trained model + data/raw ZIPs; --limit N to smoke)
python3 runs/run_tooluse_eval.py               # tool-use agent leg → runs/tooluse_eval/
                                               # (claude CLI only, scenarios are in-repo; --limit N to smoke)
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

