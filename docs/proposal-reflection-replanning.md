# Proposal Reflection & Replanning (2026-07-23)

Paste-ready reflection and replanning notes keyed to each milestone point in the
front-matter Vaibhav added to `SandBox Project.docx`. Each block below matches a
point in the doc's "Project milestones" section; drop the **Reflection** and
**Replanning** text under the matching prompt in the Google Doc. Point 1(1) is
already filled in in the doc and is reproduced here unchanged so the structure is
complete — do not overwrite it.

Grounded in the current repository state: the 2026-07-21 adversarial review (15
findings, all remediated), the pinned-environment regeneration, and the
LLM-judge / tool-use legs added 2026-07-22 (report §6.8, §6.9). Numbers cited
here come from committed run artifacts.

---

## 1. Theory milestones (problem formulation)

### (1) T-MDP
*(already filled in by Vaibhav — reproduced unchanged)*

**Reflection:** This part of the project has been progressing well.

**Replanning:** Not needed.

### (2) Context-based risk score

**Reflection:** Implemented and exercised. The seeded noise model
(`risk_noise.py`) draws Gaussian perturbations of the risk score, and the
security batch sweeps five noise levels (σ = 0.00–0.20). The horizon-dependent
exponential (monotonically increasing hazard) named in the proposal was
specified but not built — the sandbox currently treats per-event risk as i.i.d.
rather than horizon-increasing. One empirical finding qualifies this milestone:
on the real command-line data the learned risk scores are near-binary (only ~7 of
12,409 events fall between 0.1 and 0.9), so the "risk sampled from a known
distribution" abstraction is genuinely exercised only in the synthetic
file-deletion testbed, not in the security domain.

**Replanning:** Minor. Either implement the horizon-dependent exponential
distribution so the mid-range risk regime — the band where the T-MDP threshold
actually operates — gets tested, or explicitly scope the milestone: risk
sampling is validated in the file-deletion testbed, while the security domain
uses learned (near-binary) scores. Recommend the former if time permits, since
it directly stresses the policy's interesting region.

### (3) Risk-aware optimal policy

**Reflection:** Complete and validated — this is one of the two strongest-surviving
contributions. Value iteration over the finite T-MDP derives the block threshold
analytically from declared costs, `p* = (c_block − c_execute)/c_compromise = 0.40`,
with no manual tuning; convergence holds for the implemented sandbox model
(finite reachable state space, proper policies). The DEFER (value-of-information)
band that emerges from value iteration is a genuine third action no scalar
threshold can express. In the file-deletion domain the risk-aware policy shows a
statistically significant advantage over a fixed threshold (McNemar
p = 1.91×10⁻⁶), reproduced exactly under the pinned environment.

**Replanning:** Not needed for the core algorithm. One honest caveat surfaced by
the review and already documented in the report: on the security data the T-MDP's
executed set is a subset of the fixed-0.5 threshold's by construction (both score
each event with the same classifier), so the security-domain "advantage" is
one-sided by design and its divergence window is empty because the classifier is
near-binary — an artifact of the data, not a flaw in the algorithm. Keep the
framing that the algorithm is validated in the file-deletion testbed.

---

## 2. Empirical milestones (agent environment implementation)

### (1) Risk judge

**Reflection:** Now built and measured (added 2026-07-22; report §6.8). The
proposal specified an LLM judge combined with a domain-dependent rule scorer;
both exist — `llm_judge.py` (claude-opus-4-8 via the Claude Code CLI) and the
rule-based scorer — combined as `0.4·rule + 0.6·LLM` feeding the T-MDP gate.
Measuring the judge reversed an assumption we had written into the report: we had
asserted LLM confidence numbers are not calibrated, but on every independent
subset the LLM judge is *better* calibrated than the ML classifier (matched
overall ECE 0.066 vs 0.345; on hand-authored benign admin commands the judge's
false-positive rate at p*=0.40 is 5.3% vs the classifier's 100%). The combined
judge corrects all rule-only errors on the tool-use scenario suite.

**Replanning:** Minor. The judge is currently demonstrated on constructed
scenarios, not a public benchmark. Next: (a) score verbatim Risky-Bench /
SafeToolBench items instead of our own SafeToolBench-style scenarios; (b) add
self-consistency averaging (multi-sample) to reduce single-pass sampling noise —
the measured refusal/parse-failure rate is 0.55%. The honest remaining reason to
keep a classifier in the loop is operational (per-event latency/cost, sampling
nondeterminism, model-snapshot dependence), not calibration — §4.5 has been
updated to say so.

### (2) Tool-use agent

**Reflection:** Partially built (report §6.9). A LangChain tool-use agent leg
exists (`tooluse_agent.py`): the full gate pipeline (rule + LLM → T-MDP →
PROCEED/STOP/DEFER) runs with a sandboxed mock search tool, and five live agent
transcripts show the gate stopping risky actions (e.g. recursive home-directory
deletion, data exfiltration) while allowing safe ones. What is *not* yet done as
the proposal specified: the "validated against the correct answer in the dataset"
loop — the agent's task-completion accuracy on a reasoning/QA dataset, grounded
via the search tool, is not measured; the current evaluation scores gate
decisions, not answer correctness, on 40 hand-authored scenarios.

**Replanning:** Needed to fully meet the proposal. Wire the tool-use agent to a
reasoning-task dataset (e.g. Risky-Bench reasoning items), score answer
correctness with search-tool grounding, and report the safety–utility tradeoff
(task accuracy vs risky-action rate) rather than gate decisions alone.
Alternatively, scope this leg down to the gate demonstration and state that
reasoning-task validation is future work. Given the Aug 9 deadline, recommend the
scoped version unless a teammate owns the QA-accuracy loop this week.

### (3) Command-line agent

**Reflection:** The most mature leg — it is essentially the full security
pipeline — but also the one the review deflated the most. The command-line domain
scorer (rule-based labeling + calibrated classifier) and the T-MDP gate are
complete and evaluated on 15 held-out OTRF ZIPs. However, once labeling errors
were corrected (438 of the original 618 "malicious" training events were
VirtualBox housekeeping polls, now removed), the security classifier is
behaviorally identical to a 21-process whitelist rule (100% agreement on 8,410
events), its F1 (0.189) falls below a trivial 3-process baseline, and it produces
a 100% false-positive rate on hand-authored benign admin commands. The rule-based
anomaly detector works; the ML layer adds no measurable value over the whitelist
on this corpus. Also note this leg is offline log replay — no live LLM executes
commands; BLOCK is simulated on recorded events.

**Replanning:** Needed. (a) The only way to demonstrate real value is an
out-of-lab evaluation on a non-OTRF corpus — an EVTX-ATTACK-SAMPLES adapter
already exists, and DARPA OpTC is the stretch target; same-lab "held-out" ZIPs
are not out-of-distribution (12 of 15 eval ZIPs share the training lab's hosts,
operator, and recording day). (b) Obtain a captured (not authored) benign-traffic
corpus to get a real false-positive rate. (c) Optionally close the loop with an
actual LLM command-line agent proposing commands into the gate, to match the
proposal's "LLM in a sandbox" framing rather than pure replay. Item (a) is the
highest-leverage single experiment remaining for the final report.

---

## 3. Next steps

Given the progress made over the past weeks, the remaining work for the final
report (due Aug 9) is prioritized as follows:

1. **Out-of-lab evaluation (highest priority).** Run the frozen labels-first
   protocol on a non-OTRF corpus (EVTX-ATTACK-SAMPLES; DARPA OpTC if time
   allows). This is the only experiment that can show the classifier generalizes
   beyond one lab environment, and it directly addresses the review's central
   finding.
2. **Benchmark-verbatim tool-use / risk-judge evaluation.** Replace our
   SafeToolBench-style scenarios with verbatim Risky-Bench / SafeToolBench items
   so the risk-judge and tool-use numbers are comparable to published results.
3. **Close the reasoning-agent validation loop** (or formally scope it out):
   measure tool-use task accuracy with search-tool grounding.
4. **Theory polish.** Implement the horizon-dependent exponential risk
   distribution to exercise the mid-range regime, and regenerate the
   file-deletion cost sweep under the pinned environment.
5. **Report finalization.** Fold §6.8/§6.9 and the above results into the final
   report; the draft is already rewritten from the regenerated, pinned-environment
   artifacts and honestly discloses every corrected result.

The two contributions that survive scrutiny cleanly — the cost-derived T-MDP
policy (with its DEFER band) and the file-deletion significance result — should
anchor the narrative; the security-classifier results are presented honestly as
whitelist-equivalent within one lab, with out-of-lab generalization as the
open question.
