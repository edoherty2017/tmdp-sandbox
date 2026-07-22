# Response to the 2026-07-21 Adversarial Review — Findings F1–F15

This document is the authors' formal response to the 22-agent adversarial review of
2026-07-21 (`docs/review/2026-07-21-adversarial-review-findings.md`). All 15 findings were
upheld by the review's own advocate pass, and we accept all 15. For each finding we state:
(a) the verdict we acknowledge, (b) any factual sub-claims we rebut, with citations,
(c) the code fix applied, (d) the report fix applied, and (e) what remains open.

**Artifact vintage.** Every number stated as a *current* result in this document comes from
the artifacts regenerated on 2026-07-21 in the pinned environment (Python 3.14.3,
scikit-learn 1.9.0, numpy 2.5.1, pandas 3.0.3, joblib 1.5.3; versions recorded inside each
results file) under `runs/` and `data/processed/train_stats.json`, produced after all code
fixes. Numbers quoted from the review (e.g. "438/618 vboxservice mislabels", "old headline
F1=0.973") describe the pre-fix pipeline and appear only with that attribution. The
consolidated edit specification is `docs/review/2026-07-21-fix-plan.md`; code, artifacts,
report/README edits, and review documents land as the four-commit series described in its
Part F.

## Summary: what the corrected pipeline shows

We state the headline consequence plainly, because it is the most important fact in this
response: **the corrections the review demanded collapse the flagship evaluation result.**
The review was right not only about the individual defects but about their joint effect.

| Quantity | Pre-fix pipeline (as reviewed) | Regenerated (pinned env, corrected labels, real context) |
|---|---|---|
| Malicious training pool | 618 (438 of them VBoxService housekeeping polls, per F8) | 144 |
| Large independent eval P / R / F1 | 1.000 / 0.947 / 0.973 | **0.1046 / 0.955 / 0.1886** (n=8,410; FP=7,077) |
| Model vs 21-process whitelist rule | 100% agreement (F1's charge) | **still 100% agreement (8,410/8,410)** |
| Trivial 3-process whitelist F1 | 0.9988 (review's computation) | **0.1956 — still beats the model (0.1886)** |
| Hard-benign FP rate at p*=0.40 | eval did not exist | **152/152 = 100%** (both context modes) |
| Security McNemar b per sigma | 6/6/3/2/4 (report) vs 0/0/0/0/3 (review re-run) | **0/0/0/0/3; all Holm-adjusted p = 1.0** |
| File-deletion McNemar (sigma=0.15) | b=20, c=0, p=1.91e-6 | **unchanged: b=20, c=0, p=1.907e-6** |
| Sequential ben-allow gain | 0.209→0.978, Wilcoxon p=9.8e-84 | **0.2091→0.9782; exact sign test +498/0/−0, presented as descriptive** |

Two pillars survive regeneration intact: the T-MDP architectural contribution (cost-derived
thresholds, the value-of-information defer band, and the sequential block architecture,
whose gain the new threshold-sequential arm shows is decision-layer-agnostic), and the
classifier-independent file-deletion significance result, which reproduced exactly. The ML
classifier's claimed detection ability does not survive: on honest labels with real context
windows it is behaviorally a process-name whitelist, and on a benign corpus of non-whitelist
admin activity it produces a false positive on every event at the deployed threshold. The
rewritten report presents this as the finding it is, in the same disclosure-forward voice as
the existing §6.7.1 retraction.

---

## F1 — Headline eval behaviorally identical to a 21-entry whitelist; empty context windows

**(a) Verdict.** Upheld; acknowledged in full. The flagship evaluation as published was
bit-identical to the rule "process not in `_BASELINE_PROCESSES`", and every event was scored
with an empty context tuple, so the advertised context-window features were never used.

**(b) Rebutted.** Nothing. Every factual claim reproduced.

**(c) Code fix.** `runs/run_large_independent_eval.py` now scores every event with its real
preceding k=10 context window in recorded ZIP order; emits trivial baselines
(always-malicious, always-benign, 21-entry whitelist rule, 3-process whitelist),
model-vs-whitelist agreement, Wilson CIs, and a seeded cluster bootstrap into
`results.json`; and its docstring no longer claims label/feature independence. The new
`runs/run_hard_benign_eval.py` (finding F1 fix 6, shared with F6) provides the benign
corpus of non-whitelist admin activity the review required.

**(d) Report fix.** §6.7.2 is rewritten around the regenerated run: n=8,410 (866 malicious /
7,544 benign, 12 techniques, 15 ZIPs), P=0.1046, R=0.955, F1=0.1886. The trivial-baseline
table is included, and the headline states the equivalence explicitly (F1 fix 7): the model
agrees with the 21-process whitelist rule on **8,410 of 8,410 events (100.0%)**, its F1 is
below the trivial 3-process whitelist (0.1956) and barely above always-malicious (0.1867).
The T1003.003 failure analysis is rewritten from the new run — the old "EID 4656/4663
object-access records" claim was factually wrong (the review found 136/163 of those FNs
were Sysmon EID 10 events), and the current failure mode is the opposite: 7,032 false
positives on the 7,034 benign events in that ZIP (precision 0.0414). The abstract is
rescoped accordingly, and the hard-benign result (152/152 = 100% FP at p*=0.40 in both
context modes; 142/152 = 93.4% at p*=0.50 with context) is cited wherever precision was
previously claimed.

**(e) Open.** An out-of-lab evaluation (EVTX-ATTACK-SAMPLES or DARPA OpTC) is the only way
to demonstrate that the ML pipeline adds value over a frozenset; nothing in the current
corpus does.

## F2 — Training labels are a deterministic function of the features; CV, score bimodality, and calibration are circular

**(a) Verdict.** Upheld. Labels are a deterministic, ambiguity-filtered function of the
feature inputs; CV F1 is a floor, not an achievement.

**(b) Rebutted.** Nothing material. We adopt the advocate's two refinements (the
Signed-field token is a real Sysmon field, and the shuffle-before-extraction issue destroys
context signal rather than leaking labels), both already recorded in the findings.

**(c) Code fix.** The label rules themselves changed under F8 (source/mask-aware EID-10
rule in `src/tmdp_sandbox/preprocessing.py`; `feat__has_vm_read` in
`src/tmdp_sandbox/context_window.py`), and the model was retrained. No fix removes the
circularity — it is structural to auto-labeling — so the fix is disclosure.

**(d) Report fix.** §2.3, §6.1, §7.2, and §9 replace "highly distinctive attack patterns" /
"property of the data distribution" with the true mechanism, citing the review's verified
facts (zero conflicting labels across 2,294 unique feature signatures; a 5-feature lookup
achieves F1=0.971 on the old corpus). The regenerated CV is **exactly** perfect —
P=R=F1=1.000±0.000 (5-fold) on the corrected corpus of 11,935 events (11,791 benign / 144
malicious, `data/processed/train_stats.json`) — which makes the circularity caveat *more*
acute, and the report says so: shrinking the malicious class to 144 rule-pure events removed
even the old run's residual fold variance. In-distribution calibration is recast as
self-agreement with the auto-labeler. Every CV citation carries the circularity caveat; the
0.997-vs-0.998 inconsistency is gone with the old numbers.

**(e) Open.** A group-wise (per-ZIP) or deduplicated CV number has not been produced; the
report instead states the duplication facts. Low priority given that CV is no longer cited
as evidence of anything.

## F3 — "Committed artifacts contradict the report"

**(a) Verdict.** Upheld as to its core: the noise-sweep/McNemar table was not reproducible,
borderline-count metrics were library-version-sensitive, and the environment was unpinned.
That was our responsibility and is now fixed.

**(b) Rebutted.** The framing "committed artifacts contradict the report" was false: **no
run artifacts were ever committed.** As the review's own advocate verified, `.gitignore`
excluded `runs/*/`, `data/`, and `models/`, and `git ls-tree -r HEAD` showed only the 12
run scripts and zero JSON artifacts; the "contradicting" files were regenerated *in the
review environment itself*, six weeks after the report commit. The review also confirmed
that the regeneration reproduced the CV table to four decimals, the large-eval technique
rows byte-identically, the sequential result bit-identically, and the file-deletion
McNemar exactly — so "central empirical claims irreproducible" was overbroad. What
genuinely failed to reproduce was the b-column of the security McNemar table and the DEFER
count, both resting on single-digit borderline scores.

**(c) Code fix.** `pyproject.toml` pins exact versions (scikit-learn==1.9.0, numpy==2.5.1,
pandas==3.0.3, joblib==1.5.3); every run script records `library_versions` in its output;
`.gitignore` is restructured so the small artifacts (`results.json`, `summary.txt`,
`mcnemar.json`, `ground_truth_labels.json`, `train_stats.json`) are committed, honoring
§8.6's promise.

**(d) Report fix.** All tables regenerate from the single pinned-environment run set. The
current security McNemar table is b = 0/0/0/0/3 across sigma = 0.00–0.20, c=0 everywhere,
all Holm-adjusted p = 1.0; the abstract and §6.3 now make the tie-aware,
environment-qualified statement the review specified. DEFER activity is stated from the
artifact: 170 of 15,000 episodes (1.13%), 241 DEFER events, all in the tmdp-p0.40 arm. A
§7.5 bullet states that metrics carried by single-digit borderline counts are not stable
across library versions and names the pinned versions.

**(e) Open.** The original-environment model and artifacts were never archived, so the old
b=6/6/3/2/4 table is now unreproducible in principle; the report retains it only as
attributed history. Regression tests pinning the new label rules (see F8) are open.

## F4 — McNemar p-values computed with a wrong-df formula

**(a) Verdict.** Upheld. `exp(-chi2/2)` is the 2-df survival function; every printed
p-value in old §6.3 came from it, and §5.5 promised an exact test the code did not perform.

**(b) Rebutted.** Two points, both from the review's own advocate analysis, which we adopt:
the error's direction was **against** our method — the inflated p-values made the T-MDP look
worse, so there is no cherry-picking narrative — and "flips the paper's significance
conclusion" was overstated, since the nominally significant rows do not survive
Holm–Bonferroni across the correlated five-sigma family.

**(c) Code fix.** `runs/run_security_batch.py` computes the exact two-sided binomial
McNemar p via `math.comb`, keeps the correct 1-df chi-square tail as a secondary reference,
applies Holm–Bonferroni across the five sigma rows (one correlated family — the rows share
the same 500 scenarios under common random numbers), and no longer labels the column
"p (approx)".

**(d) Report fix.** §5.5's "McNemar exact test" is now true of the code. The regenerated
table is fully degenerate at sigma ≤ 0.15 (b=c=0, p_exact=1.0); the only discordance is
b=3, c=0 at sigma=0.20 (p_exact=0.25, Holm-adjusted 1.0). No security-domain row is
significant, and the report says so without the old wrong-formula numbers. §7.5 gains the
correlated-family bullet (per-row p-values must not be combined; the affirmative
file-deletion claim survives any plausible correction).

**(e) Open.** None.

## F5 — 70% of eval malicious ground truth from one ZIP via a bare-substring T1047 rule

**(a) Verdict.** Upheld. The bare `'wmi'`/`'create'` substrings labeled routine WmiPrvSE
provider-host boilerplate and generic audit records malicious; the old headline recall
partly measured two artifacts agreeing on boilerplate text.

**(b) Rebutted.** Two details, per the review's own advocate, without conceding substance:
the generic audit-record count is **2,090, not 2,113** (the criticism's own EID breakdown —
4658×1,053 + 4656×527 + 4663×510 — sums to 2,090), and only **2** of the 2,124 wmiprvse
events carry the literal `-secured -Embedding` command line; the rest matched `'wmi'` via
the WmiPrvSE path embedded in audit-message text, which is substantively the same defect.

**(c) Code fix.** The T1047 rule in `runs/run_large_independent_eval.py` drops bare
`'wmi'`/`'create'`; malicious now requires wmic.exe or specific tokens (win32_process,
iwbemservices, execmethod, invoke-wmimethod), and generic EID 4656/4658/4663 audit records
return None.

**(d) Report fix.** In the regenerated run T1047 shrinks from 2,362 malicious events to
**1** (with 42 benign, precision 0.0233), and §6.7.2 reports overall metrics with and
without T1047 (F1 0.1886 vs 0.1893), macro-averaged recall over techniques (0.9808),
per-technique n prominently, and Wilson CIs on small-n rows. The "five of nine techniques
achieve recall=1.000" and "128× larger" framings are gone. The table lists all 12
techniques, including the previously omitted T1069.001 and T1087.001.

**(e) Open.** T1547.001 still has zero malicious events under the current rules (141
benign, degenerate row) — a persisting labeling-coverage gap the report annotates so the
0.0 row is not misread as a model failure.

## F6 — Benign eval set is whitelist-only by construction; precision=1.000 guaranteed

**(a) Verdict.** Upheld. Every benign clause in `label_by_technique` was a
baseline-whitelist membership test, so the old eval structurally could not record a
whitelist false positive, and the T1053.005 row validated the 0.99 EID override against a
label rule that is the same rule.

**(b) Rebutted.** Nothing.

**(c) Code fix.** `runs/run_large_independent_eval.py` labels agent/hypervisor polls benign
so model FPs are countable (see F8), and the new `runs/run_hard_benign_eval.py` evaluates a
152-event hand-authored corpus of benign Windows admin activity across 11 categories, 34
processes, all outside the 21-entry whitelist, against the model and both whitelist
baselines.

**(d) Report fix.** Precision is reported as FP counts with Wilson intervals plus the
benign-composition disclosure (current run: FP=7,077 of 7,544 benign; precision Wilson 95%
CI [0.0981, 0.1116]). The hard-benign result is presented plainly: at the deployed
p*=0.40 the model flags **152/152 (100%)** of the benign admin events in both context
modes; only at p*=0.50 with a self-consistent context stream does it fall to 142/152
(93.4%). The model never says benign for any non-whitelist process. T1053.005 is annotated
(the EID 4698 label rule coincides with the deterministic 0.99 override, which originated
from the retracted 30-event eval). The report also carries the artifact's own limitation:
the corpus is hand-authored for this remediation, not captured telemetry, and does not
estimate a deployment FP rate.

**(e) Open.** A captured-telemetry benign corpus (out-of-lab eval) remains the real test.

## F7 — One-sided-by-construction comparisons; significance imported from the file-deletion domain; 0.4545 error

**(a) Verdict.** Upheld as scoped by the advocate: the report cited design-guaranteed
direction ("c=0 across all noise levels", "never worse") as empirical findings, misdescribed
the deployed policy's defer band, misstated the VI tolerance, and
`docs/results/fair-comparison-writeup.md` contained a stale implicit-threshold value
(0.4545 for 0.4000).

**(b) Rebutted.** We adopt the advocate's rebuttals of the criticism's overreach, which the
findings document already records: the derivation-not-inference thesis is stated throughout
the report; the threshold-0.3 "identical safety at lower cost" claim fails at sigma ≥ 0.15,
where the defer band keeps episodes alive (a decision no single threshold expresses); and
the "engineered domain" charge is defused by the per-ambiguity decomposition of the
project's own data (see (d)).

**(c) Code fix.** `docs/results/fair-comparison-writeup.md:23` corrected 0.4545 → 0.4000
(fix A7; verified landed). The tolerance statement is a report fix (1e-6 is the production
default; 1e-9 appears only in unit tests).

**(d) Report fix.** The abstract, §3.4, §6.4, §7.1, and the Figure 2 caption now state the
subset property: under matched noise with p* < 0.5, the T-MDP's executed set is a subset of
threshold-0.5's, so c=0 is structural and b counts one-sided divergences; "cannot be worse
by construction; the plot shows the magnitude." The mechanism correction is in §3.4: the
deployed policy defers on (0.30, 0.50] (the VI value-of-information band); it does not
block at 0.40. The writeup gains a paragraph after the McNemar result stating the
structural one-sidedness caveat and the per-ambiguity decomposition recomputed from the
regenerated `episodes_all.jsonl`: of the 20 discordant pairs at sigma=0.15, 11 are from the
ambiguity=0.0 stratum, 8 from 0.5, 1 from 1.0, while the pooled both-catastrophe count of
143 is dominated by the ambiguity=1.0 control (99/100). The file-deletion citation is
recharacterized: direction guaranteed by design; the exact test (b=20, c=0, p=1.907e-6,
reproduced exactly under regeneration) certifies the divergence window is populated.

**(e) Open.** Nothing specific; note the security-domain McNemar is now degenerate anyway
(F3/F4), so the file-deletion domain carries the entire significance weight, with the
above caveat attached wherever it is cited.

## F8 — 70.9% of the malicious training class was VirtualBox housekeeping

**(a) Verdict.** Upheld. This was the central label defect: 438/618 (70.9%) of malicious
training events were VBoxService EID-10 polls (GrantedAccess=0x1400, no PROCESS_VM_READ)
mislabeled by a source- and mask-blind rule, and none of the 8 training scenarios contains
credential-access activity — so all credential-access "recall" was learned from mislabeled
housekeeping.

**(b) Rebutted.** Nothing. We note (with the advocate) that the mechanism is worse than the
criticism's "VM-only signature" framing: the learned rule is a portable "any lsass/winlogon
handle = credential theft" false-positive generator that fires on AV/EDR agents.

**(c) Code fix.** `src/tmdp_sandbox/preprocessing.py`: the EID-10 rule is source- and
mask-aware — malicious requires dump-capable rights (PROCESS_VM_READ, 0x0010) and a
non-baseline/non-agent source; 0x1400-only masks return None; vboxservice.exe/msmpeng.exe
are recognized as agent processes. `feat__has_vm_read` added in
`src/tmdp_sandbox/context_window.py`. The same source/mask logic is applied in
`label_by_technique` (`runs/run_large_independent_eval.py`), and agent polls are labeled
benign so model FPs are counted. The model was retrained on the corrected labels.

**(d) Report fix.** The malicious training pool is now honestly **144 events** (was 618);
the abstract and §4.2 describe the corrected corpus and disclose the original mislabeling
with the review's numbers, attributed to the pre-fix pipeline. §6.7.2 and §7.5 state that
prior credential-access recall was learned entirely from mislabeled housekeeping, and the
new T1003.x rows are presented as the honest numbers — which are poor in the direction that
matters: T1003.003 precision 0.0414 (7,032 FP), T1047 precision 0.0233. The stale
11,597/568 counts and the no-op downsampling sentence are gone (with F9/F15).

**(e) Open.** Regression tests pinning the new EID-10 rule's behavior (agent 0x1400 poll →
None; VM_READ + non-agent source → malicious) are not yet written; listed in the fix plan's
commit 1 scope and still outstanding.

## F9 — Calibration claims vacuous, measured on the wrong scorer

**(a) Verdict.** Upheld. ECE was structurally insensitive to calibration at p*=0.40;
calibration was measured on the raw pipeline while the deployed scorer adds a hard-coded
0.99 EID override; the downsampling description was false.

**(b) Rebutted.** Nothing beyond the advocate's recorded narrowing (the report did print
the full reliability table and flag the n=2 bin).

**(c) Code fix.** Calibration re-run in the pinned environment on the corrected corpus;
versions recorded. No scoring-path change: the override is now *described* correctly rather
than removed.

**(d) Report fix.** §6.5 reports the regenerated result, which is *more* degenerate, and
says so: 8 of 10 bins are empty in both sets; only [0.0–0.1] and [0.9–1.0] are populated;
ECE=0.0 and Brier=0.0 exactly, MCE=0.0004 (in-distribution) / 0.0005 (cross-technique).
The old n=2 mid-range bucket (MCE=0.5533) no longer exists because no event anywhere in
either set scores in (0.1, 0.9). The report states the consequence without softening:
**there is no empirical support for p*=0.40 being a meaningful probability on this
corpus** — the threshold's justification is purely the cost derivation. The scorer
mismatch is disclosed (the 0.99 override is a deterministic rule outside the calibrated
scorer, untestable here, with real-world FP risk for benign admin EIDs); "operationally
valid" claims are rescoped; the conclusion's "ECE confirms p*" chain is removed, as are
the downsampling sentence and the ECE 0.0002/0.0003 vintage mixing.

**(e) Open.** The uncalibrated-vs-sigmoid-vs-isotonic ablation was not run; §7.2's
"property of the data" claim is hedged as untested rather than asserted.

## F10 — Planner cost 10× smaller than evaluator cost

**(a) Verdict.** Upheld at minor severity: a framing/documentation gap. The flagship
experiment's planning cost was back-derived from the target threshold, and §7.5 never
flagged the mismatch.

**(b) Rebutted.** The "laundering" narrative. The matched-cost configuration
(planner=evaluator=100, p*=0.04) **was already run and published in Appendix C — and it
favors the framework** (regenerated: mal-exec 0.000 with evaluated cost 7.716 for tmdp /
5.876 for tmdp-nodefer at c=100, versus 10.138–10.218 at the pinned p*=0.40 operating
point), so the c=10 choice was not result-flattering. And "quietly changed the
proposal-of-record" fails because the proposal was self-contradictory: `cs5100-proposal.md`
line 173 specifies c_compromise=100 while line 178 declares "Threshold-0.4 (its implicit
operating point)", which requires c=10; the implementation resolved the contradiction by
keeping the proposal's stated operating point for planning and its damage figure for
evaluation.

**(c) Code fix.** None required; the cost sweep was regenerated in the pinned environment
(`runs/security_cost_sweep/`).

**(d) Report fix.** §5.2/§7.4 state the planner-vs-evaluator mismatch and the wedge-design
rationale; §7.5 gains the limitation bullet; the abstract mentions the evaluator's c=100;
the over-claim that the flagship threshold was "derived rather than chosen" is rewritten
(for that experiment the cost was back-derived from the target threshold); Appendix C's
matched-cost row is cross-referenced as the honest-calibration result, with the
derived-not-tuned property carried by Appendices B/C and the file-deletion domain
(planner=evaluator=10). Note the regenerated Appendix C also changed one number the old
draft cited: DEFER-vs-nodefer ben-allow at c=50 is now 0.141 vs 0.077 (was 0.141 vs 0.079).

**(e) Open.** None.

## F11 — No trivial baselines, 98.3% exclusion, no confidence intervals

**(a) Verdict.** Upheld. None of the baselines, the exclusion funnel, or interval estimates
appeared where the headline claims lived.

**(b) Rebutted.** One insinuation, using the review's own computation: duplication did not
inflate the point estimate — deduplication by command line **raises** F1 (the advocate
computed 0.991 vs the 0.973 headline on the pre-fix run). The same holds, far more
dramatically, in the regenerated run: dedup-by-cmdline gives P=0.9267 / R=0.962 /
F1=0.944 versus the pooled 0.1886, because the FP flood is dominated by repeated command
lines. Clustering dominates the uncertainty; it does not flatter the headline.

**(c) Code fix.** `runs/run_large_independent_eval.py` emits the trivial baselines,
model-vs-whitelist agreement, recall/precision Wilson CIs, a seeded 10,000-iteration
cluster bootstrap over ZIPs for F1, dedup-by-cmdline metrics, and the per-ZIP exclusion
funnel.

**(d) Report fix.** §6.7.2 (retitled away from "Authoritative Result") discloses the
funnel — 230,676 events in the 15 ZIPs, 8,410 labeled, 222,266 excluded (96.35%) — with the
per-ZIP breakdown in an appendix and the selection effect stated plainly. The baseline
table shows the model against always-malicious (F1=0.1867), always-benign (0.000), the
21-process whitelist (identical to the model), and the 3-process whitelist (0.1956, better
than the model). Uncertainty is quantified: recall Wilson 95% CI [0.939, 0.967]; precision
Wilson 95% CI [0.0981, 0.1116]; F1 cluster-bootstrap 95% CI **[0.094, 0.989]** — an interval
the report describes as nearly vacuous, which is itself the honest statement of how little
n=15 ZIP clusters constrain the metric. Small-n technique rows are annotated rather than
counted in headline claims.

**(e) Open.** Folded into the out-of-lab evaluation item.

## F12 — Tune-on-test contamination of the cross-technique result

**(a) Verdict.** Upheld. The 0.639→0.815 improvement came from editing features *and* label
rules against the held-out ZIPs and re-scoring the same ZIPs; by our own §8.6 rule-5
standard that is in-sample measurement.

**(b) Rebutted.** Nothing (the advocate's narrowing — retaining the fixes in later evals was
protocol-compliant, and the 30-event eval was already retracted — is recorded in the
findings and reflected in the report text).

**(c) Code fix.** `runs/run_cross_technique_eval.py` re-run against the corrected labels in
the pinned environment.

**(d) Report fix.** §6.1.1 is retitled as a development/diagnostic evaluation and carries
the tune-on-test disclosure; the first-pass 0.639 is identified as the only untainted
cross-technique number. The regenerated run gives **F1=1.000 overall (n=1,484; 90
malicious; FP=0, FN=0)** — the old "honest generalization gap" narrative (F1=0.921, recall
0.853) no longer exists and is not reused. The report is explicit that a perfect score on
a diagnostic, tune-on-test split under rule-derived labels is evidence of label/feature
alignment, not generalization, and §2.3/§8.1/conclusion citations of 0.921 as
generalization evidence are removed.

**(e) Open.** A clean cross-technique evaluation on an untouched technique pair (frozen
lists, never diagnosed against) has not been run.

## F13 — "Held-out" is not out-of-distribution; "no independent dataset exists" is self-inconsistent

**(a) Verdict.** Upheld. 14/15 eval ZIPs share the training lab environments and operator;
one was recorded 23 minutes before a training capture; the sole out-of-environment ZIP
produced the worst behavior; and the line-199 justification was inconsistent with our own
§6.7.2 methodology.

**(b) Rebutted.** Three factual details, per the advocate, without conceding substance: the
obfuscation prevalence is **51/618 = 8.3%** by the repo's own `_OBFUSCATION_RE` (not 26/618
= 4.2%); the Empire eval ZIP count is **12, not 11** (13/15 including Covenant are .NET C2
sessions — the corrected count strengthens the monoculture point); and LANL Unified Host
lacks per-event red-team labels (DARPA OpTC is the applicable example).

**(c) Code fix.** None (scope finding). The EVTX-ATTACK-SAMPLES adapter already ships in
`src/tmdp_sandbox/preprocessing.py`, which is precisely why the old "no such dataset is
publicly available" claim could not stand.

**(d) Report fix.** §6.7.2's guarantee 3 is reworded to ZIP-level disjointness only, with
the host/operator/timing facts stated (12 theshire-trio ZIPs, 1 mordor.local, 1
WORKSTATION5/wardog; same operator; one ZIP 23 minutes before a training capture; 12/15
Empire + 1 Covenant). §4.5's "no such dataset" sentence is replaced with the honest
statement that the frozen `label_by_technique` protocol could be applied to
EVTX-ATTACK-SAMPLES or DARPA OpTC, listed as the required next step. The headline is
rescoped everywhere to "held-out-ZIP evaluation within the Mordor/theshire lab
environment," and §7.5 discloses the verbatim benign-background overlap (367/91/51
identical command lines) that inflated the old FP=0.

**(e) Open.** The out-of-lab evaluation itself — the largest open item in this response.

## F14 — Sequential/DEFER results are harness artifacts; missing comparison arm

**(a) Verdict.** Upheld as to the missing threshold-sequential arm, the decorative
Wilcoxon, the unreconciled cost display, and the DEFER harness semantics (no review
resolution, no posterior re-decision, deferred-malicious counted as blocked by definition,
c_defer=0.5 < c_execute=1).

**(b) Rebutted.** The "strawman baseline" charge: **stop-on-first was the incumbent
architecture used in every prior experiment, not a constructed strawman**, and the report
explicitly attributed the gain to the architecture, not the T-MDP (the old §6.6 table
showed oracle-stop capped at ~0.214 ben-allow precisely to make that point, and the
abstract credited "a sequential block architecture"). The review's own advocate also recorded that the Wilcoxon
approximation erred in the conservative direction and that the benign-allow metric does
penalize over-deferral. The valid core — that the missing arm let the result be over-read —
we accept and have fixed by adding the arm.

**(c) Code fix.** `runs/run_sequential_eval.py`: threshold-0.5-sequential arm added; exact
one-sided sign test on paired per-scenario differences replaces the Wilcoxon; per-decision
cost reported per arm; versions recorded.

**(d) Report fix.** §6.6 reports the regenerated six-arm table. The new arm confirms the
gain is decision-layer-agnostic: threshold-0.5-sequential reaches ben-allow 1.0000 (vs
0.2138 stop-on-first) just as tmdp-sequential reaches 0.9782 (vs 0.2091) — and it also
executes 1 malicious event in 498 scenarios (mal-exec 0.0020), the only nonzero
malicious-execution among sequential arms, whereas tmdp-sequential stays at 0.000; the
report notes both facts. The statistical claim is downgraded to what it is: exact sign
test +498/0/−0, p=1.222e-150 for both pairs, presented per the artifact's own caveat as
structural and descriptive, not inferential (stop-on-first forfeits every event after its
first block). The cost reconciliation is stated (episode cost has no credit for completed
benign work; per-decision cost is lower for the sequential arms, 1.791 vs 1.870 for tmdp
and 1.810 vs 1.879 for threshold), the §3.3 line-89/103 contradiction is resolved, DEFER's
operational semantics (skip at cost 0.5, no resolution, no re-decision) are disclosed in
§3.3/§5.5, and §8.2's "all DEFER episodes correctly prevent malicious execution" is
reworded as true by metric construction.

**(e) Open.** A cost sweep under sequential semantics — to measure DEFER's residual value
once continuation is no longer confounded with stop-on-first — has not been run, and the
harness still does not simulate review resolution or posterior re-decision. Both are
listed as future work, not results.

## F15 — Framing oversells an offline classifier; pervasive numeric hygiene failures

**(a) Verdict.** Upheld as to both the offline-replay framing gap and the numeric hygiene
pattern. For a post-retraction project whose selling point is auditable rigor, report
tables disagreeing with their own artifacts was a major defect; we accept that fully and
have made the mechanical process change (single artifact vintage, committed artifacts,
pre-submission diff of every report number against `runs/`).

**(b) Rebutted.** Two sub-claims, with citations. First, "the archived proposal never
mentions the dropped LLM judge or LangChain" grepped the wrong document: the team's
proposal of record is **'SandBox Project.docx'** (repo root; extraction in
`docs/source/`), and the LLM-judge requirement is verbatim at
`docs/source/SandBox_Project_extracted.md:43` — "a risk assessment module, which features
an LLM judge as the simplest instance" — while "LangChain" appears in the docx's
`word/document.xml` (and as a langchain.com URI in the PDF). The README's open decision
items are grounded in that document, and the README now points to it explicitly so future
readers grep the right file. Second, "118/118 tests" was the correct count (verified by the
review itself on a fresh clone); it was Appendix A's "113" that was stale.

**(c) Code fix.** The single-vintage regeneration and version recording (F3) are the
mechanical fix; the test count in Appendix A is corrected to the post-fix suite's count.

**(d) Report fix.** The full reconciliation pass: every number in the report now traces to
the regenerated artifacts (corpus 11,935 = 11,791/144; DEFER 170/15,000 = 1.13%; McNemar
b=0/0/0/0/3; one calibration vintage; 12-technique eval table; figures and captions
regenerated — the hardcoded annotation strings in `generate_figures.py` (old ECE/Brier/n,
the retracted Wilcoxon p, the pre-fix cluster counts) were replaced with artifact-current
values and all five PNGs re-rendered). The offline-replay methodology is made explicit
in the abstract and a §7.5 bullet: BLOCK is simulated on recorded post-execution telemetry
(EID 4688 is emitted after a process starts; 4656/4663 have no pre-execution analog), used
as a proxy for the feature set a pre-execution enforcement hook would observe. The README
H1 drops the standalone "Catastrophic Action Prevention" claim in favor of the report's
honest title, and its headline block is rewritten from the regenerated artifacts with the
whitelist-baseline and single-lab caveats.

**(e) Open.** The LLM-judge / tool-use / LangChain leg remains unimplemented — it is a
proposal requirement and stays an open decision item for the team, now correctly sourced
to 'SandBox Project.docx'.

---

## Consolidated open items

1. **Out-of-lab evaluation** (F1, F6, F11, F13): run the frozen `label_by_technique`
   protocol on EVTX-ATTACK-SAMPLES (adapter already in `preprocessing.py`) or DARPA OpTC
   and report the result, whatever it is. This is the only path to any claim that the ML
   pipeline outperforms a whitelist.
2. **Sequential-semantics cost sweep** (F14): measure DEFER's residual value under the
   sequential architecture, where its benefit is no longer confounded with episode
   continuation.
3. **LLM-judge leg** (F15): the proposal's risk-assessment module ('SandBox Project.docx')
   remains unbuilt; team decision pending.
4. **Regression tests pinning the corrected EID-10 rule** (F8): agent 0x1400 polls → None;
   VM_READ + non-agent source → malicious; whitelist-agent list membership.
5. **File-deletion cost-sweep regeneration** (F7/F10 adjacent): the Appendix B cost-sweep
   rows and the writeup's sweep table come from the original-environment run and are marked
   as such; regenerate under the pinned environment before final submission.
6. **Group-wise / deduplicated CV** (F2): optional, since CV is no longer cited as
   evidence, but would complete the disclosure.
