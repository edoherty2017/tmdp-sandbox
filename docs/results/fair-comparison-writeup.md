# Fair T-MDP Batch Results and Cost Sensitivity

## Experiment design

Primary fair-comparison batch:

- 100 seeds x 3 ambiguity levels (`0.0`, `0.5`, `1.0`) = 300 scenarios
- Two noise conditions: `sigma=0.0` and `sigma=0.15`
- Five policies: `no-termination`, `always-terminate`, `threshold-risk` oracle, `observable-threshold-risk`, `tmdp-value-iteration`
- Generator settings: `benign_count=5`, `trap_rate=0.3`, `protected_decoy_rate=0.25`
- Fair initial comparison: `catastrophe_cost=10`, `termination_cost=5`, `delete_step_cost=1`
- T-MDP implicit termination threshold: `(5 - 1) / 10 = 0.4000`
- Scripted observable baseline threshold: `risk_threshold=0.5`

Runtime artifacts (regenerated 2026-07-21 in the pinned environment — Python 3.14.3,
scikit-learn 1.9.0, numpy 2.5.1, pandas 3.0.3, joblib 1.5.3). The file-deletion domain is
classifier-independent, and every fair-batch table in this document reproduced exactly under
regeneration; no numbers changed.

- Summary JSON: `runs/fair_batch/fair_comparison_cat10/summary.json`
- Episodes JSONL: `runs/fair_batch/fair_comparison_cat10/episodes_all.jsonl`
- Cost sweep summary: `/home/doher/tmdp-sandbox-runs/cost_sweep_sigma_0p15_ambiguity_0p5/cost_sweep_summary.json`
  (original-environment run, NOT regenerated — see the vintage note in the cost sweep section)

## Interpretation

The sigma=0.15 T-MDP point-estimate advantage over `observable-threshold-risk` should be interpreted as threshold derivation rather than superior inference. With `catastrophe_cost=10`, the T-MDP derives an implicit threshold of `0.4000`, while the scripted baseline uses the hand-set threshold `0.5`. Under noise, some risky files land between those thresholds; the T-MDP terminates them while the scripted policy deletes them. The contribution is therefore that the T-MDP framework derives the operating threshold from explicit costs, while the scripted policy requires manual threshold tuning.

The ambiguity sweep is the strongest result. When observable signal quality is high (`ambiguity_level=0.0`, `sigma=0.15`), T-MDP has catastrophe rate `0.010` while `observable-threshold-risk` has catastrophe rate `0.120`. When signal quality is zero (`ambiguity_level=1.0`), both policies degrade to approximately full catastrophe: T-MDP `0.990`, observable threshold `1.000`. This supports the claim that T-MDP can extract more value from a useful risk signal, but cannot rescue a fully uninformative signal.

The oracle threshold baseline should be reported as a safety upper-bound reference, not as a fair policy comparator. Its near-zero task completion is expected because generated requested deletions include traps; the oracle terminates as soon as it sees the first trap. It frames the safety-utility axis together with `always-terminate`.

## Primary comparison with 95% confidence intervals

`observable-threshold-risk` vs `tmdp-value-iteration`, 300 episodes per sigma condition:

| sigma | policy | task rate (Wilson 95%) | unnecessary termination (Wilson 95%) | catastrophe rate (Wilson 95%) | average cost (normal 95%) |
|---:|---|---:|---:|---:|---:|
| 0.00 | observable-threshold-risk | 0.447 [0.391, 0.503] | 0.500 [0.444, 0.556] | 0.470 [0.414, 0.527] | 17.553 [16.185, 18.921] |
| 0.00 | tmdp-value-iteration | 0.447 [0.391, 0.503] | 0.500 [0.444, 0.556] | 0.470 [0.414, 0.527] | 15.603 [14.497, 16.710] |
| 0.15 | observable-threshold-risk | 0.483 [0.427, 0.540] | 0.430 [0.375, 0.487] | 0.543 [0.487, 0.599] | 18.797 [17.447, 20.146] |
| 0.15 | tmdp-value-iteration | 0.450 [0.395, 0.507] | 0.493 [0.437, 0.550] | 0.477 [0.421, 0.533] | 15.717 [14.611, 16.822] |

The unpaired Wilson intervals for the sigma=0.15 catastrophe rates overlap, so the point-estimate gap should not be interpreted from marginal CIs alone. Because every scenario is run under both policies, the appropriate comparison is paired. A paired McNemar/exact binomial test over the 300 sigma=0.15 matched scenarios gives 20 discordant pairs where `observable-threshold-risk` catastrophes and T-MDP does not, and 0 discordant pairs in the opposite direction (`both catastrophe=143`, `neither catastrophe=137`). The exact two-sided McNemar p-value is `1.91e-06` (continuity-corrected chi-square p=`2.15e-05`), so the catastrophe-rate reduction is statistically significant under the paired design. At sigma=0.0 there are no discordant catastrophe outcomes between these two policies (`p=1.0`).

Two caveats on reading that p-value (added 2026-07-21 in response to adversarial-review finding F7). First, the discordance is structurally one-sided: both policies see identical noise draws (matched seeds), and the T-MDP's implicit threshold (`0.4000`) sits below the scripted policy's (`0.5`), so every deletion the T-MDP performs the scripted policy also performs. `c=0` is therefore guaranteed by construction, and McNemar under this design can only reject in the T-MDP's favor — the exact test certifies that the divergence window between the two thresholds is populated often enough to matter (b=20 of 300 scenarios), not that the T-MDP won a symmetric contest. Second, the per-ambiguity decomposition of the paired outcomes (recomputed from the regenerated `episodes_all.jsonl`): of the 20 discordant pairs at sigma=0.15, 11 come from the `ambiguity=0.0` stratum, 8 from `ambiguity=0.5`, and 1 from `ambiguity=1.0` — the T-MDP's saves concentrate where the observable risk signal is informative. Conversely, the pooled both-catastrophe count of 143 is dominated by the `ambiguity=1.0` uninformative-signal control (99 of its 100 pairs; `ambiguity=0.0` contributes 1 and `ambiguity=0.5` contributes 43), so the pooled 143/300 figure should not be read as the failure rate in the informative regime.

## Per-ambiguity comparison at sigma=0.15

This breakdown isolates the strongest result: T-MDP reduces catastrophes most when the observable risk signal is informative, and both policies fail when the signal is fully ambiguous.

| ambiguity | policy | catastrophe rate | task completion | unnecessary termination |
|---:|---|---:|---:|---:|
| 0.0 | observable-threshold-risk | 0.120 | 0.090 | 0.840 |
| 0.0 | tmdp-value-iteration | 0.010 | 0.060 | 0.940 |
| 0.5 | observable-threshold-risk | 0.510 | 0.360 | 0.450 |
| 0.5 | tmdp-value-iteration | 0.430 | 0.310 | 0.530 |
| 1.0 | observable-threshold-risk | 1.000 | 1.000 | 0.000 |
| 1.0 | tmdp-value-iteration | 0.990 | 0.980 | 0.010 |

The low task-completion rate at `ambiguity_level=0.0` is expected under the current per-file sequential adapter. With `benign_count=5` and `trap_rate=0.3`, each generated scenario contains five benign requested deletions and two requested traps, shuffled into a seven-item order. A policy that correctly terminates at the first trap completes all benign work only if all five benign files appear before either trap: `(5/7) x (4/6) x (3/5) x (2/4) x (1/3) = 120/2520 = 0.0476`. The observed ~5% completion rate therefore reflects the random requested-deletion ordering and the adapter's inability to reorder work, not a policy deficiency. A future multi-file/global T-MDP could reason over the remaining file set and potentially complete more benign work before terminating.

## Unnecessary-termination check

The exact `0.500` unnecessary termination rate at `sigma=0.0` is not a metric artifact; it is an average over the three ambiguity strata:

| sigma | policy | ambiguity | unnecessary termination | appropriate termination | termination | catastrophe | task |
|---:|---|---:|---:|---:|---:|---:|---:|
| 0.00 | observable-threshold-risk | 0.0 | 0.950 | 0.050 | 1.000 | 0.000 | 0.050 |
| 0.00 | observable-threshold-risk | 0.5 | 0.550 | 0.040 | 1.000 | 0.410 | 0.290 |
| 0.00 | observable-threshold-risk | 1.0 | 0.000 | 0.000 | 1.000 | 1.000 | 1.000 |
| 0.00 | tmdp-value-iteration | 0.0 | 0.950 | 0.050 | 1.000 | 0.000 | 0.050 |
| 0.00 | tmdp-value-iteration | 0.5 | 0.550 | 0.040 | 0.830 | 0.410 | 0.290 |
| 0.00 | tmdp-value-iteration | 1.0 | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 |

Metric semantics: `unnecessary_termination` is true only when the policy voluntarily terminates before completing remaining benign requested work, without an attempted catastrophe and without qualifying as appropriate termination. Episodes that delete through to catastrophe are not counted as unnecessary termination. Therefore ambiguity=1.0 has `0.000` unnecessary termination because the policies usually do not stop before catastrophe; they under-terminate rather than over-terminate.

## Cost sensitivity sweep

> Vintage note (2026-07-21): this sweep's source artifact
> (`cost_sweep_sigma_0p15_ambiguity_0p5/cost_sweep_summary.json`) was produced in the
> original, pre-pin environment and has not been regenerated under the pinned library
> versions. Every other table in this document was re-verified against the regenerated
> `runs/fair_batch/fair_comparison_cat10/summary.json` and `episodes_all.jsonl`; treat the
> four rows below as indicative pending regeneration.

Fixed condition: `ambiguity_level=0.5`, `sigma=0.15`, 100 scenarios, policy=`tmdp-value-iteration`.

| catastrophe_cost | implicit threshold `(5-1)/c` | unnecessary termination | catastrophe rate | voluntary termination | task completion | average cumulative cost |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.4000 | 0.530 | 0.430 | 0.820 | 0.310 | 13.450 |
| 50 | 0.0800 | 0.800 | 0.190 | 0.980 | 0.030 | 18.130 |
| 100 | 0.0400 | 0.870 | 0.120 | 1.000 | 0.010 | 18.740 |
| 500 | 0.0080 | 0.890 | 0.100 | 1.000 | 0.010 | 55.570 |

This is the central cost-sensitivity result: as catastrophe cost rises, the T-MDP's derived threshold drops, unnecessary termination rises, and catastrophe rate falls. The T-MDP is not merely a fixed conservative rule; its operating point moves systematically with the declared safety-utility tradeoff.

## SSP statement

The current T-MDP adapter is a finite-horizon stochastic shortest-path-style expected-cost model over one requested deletion candidate at a time. Each per-candidate model has at most one inspection opportunity (`remaining_budget=1`) and then either deletes or terminates, so all induced policies are proper and reach a terminal state in at most two model decisions. The objective is undiscounted expected cumulative cost minimization with terminal states for completion, voluntary termination, and catastrophe. Because the reachable state space is finite and terminal-reaching policies exist from every nonterminal state, value iteration converges for this bounded SSP instance. This is a modeling statement for the implemented sandbox, not a general proof for arbitrary T-MDPs.

## Writeup claim to use

A careful claim supported by these results is:

> T-MDP value iteration does not infer hidden risk better than the observable risk scorer. Its advantage is that it converts explicit safety and utility costs into a principled termination threshold, and that threshold moves predictably under cost sensitivity. When the observable risk signal is informative, the T-MDP operating point can reduce catastrophes relative to a manually tuned scripted threshold; when the signal is fully ambiguous, both policies fail, exposing the dependence on signal quality.
