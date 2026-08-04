# Proposal Reflection & Replanning — FINAL (2026-07-23)

Final fill-in text for the milestones sheet in the Google Doc. The sheet's
structure and wording are final; only the empty Reflection / Replanning lines
and Section 3 get this text. Each block below is plain text in the sheet's own
format — copy the lines after each milestone name verbatim (no markdown, no
headings). Point 1(1) is already filled in on the sheet; do not overwrite it.
Do not paste this header.

---

1. Theory milestones

(1) T-MDP

Reflection: This part of the project has been progressing well.
Replanning: Not needed.

(2) Context-based risk score

Reflection: Implemented and exercised. Risk scores are perturbed with seeded Gaussian noise and the security experiments sweep five noise levels (sigma 0.00 to 0.20). The horizon-dependent exponential distribution was specified but not built; per-event risk is currently treated as independent of the horizon. On the real command-line data the learned risk scores are near-binary (only about 7 of 12,409 events fall between 0.1 and 0.9), so sampled-risk behavior is genuinely exercised only in the synthetic file-deletion testbed.
Replanning: Minor. Implement the horizon-dependent exponential distribution to test the mid-range risk regime where the T-MDP threshold operates, or explicitly scope risk sampling to the file-deletion testbed. We recommend the former if time permits.

(3) Risk-aware optimal policy

Reflection: Complete and validated. Value iteration derives the block threshold p* = 0.40 directly from the declared costs with no manual tuning, and it produces a defer band (request human inspection) that no single fixed threshold can express. On the file-deletion task the risk-aware policy significantly outperforms a fixed threshold (McNemar p = 1.91e-6), reproduced exactly under a pinned software environment.
Replanning: Not needed for the algorithm. One caveat: on the security data the comparison against a fixed threshold is one-sided by construction, because both policies score events with the same near-binary classifier, so the algorithm's advantage is demonstrated on the file-deletion task.

2. Empirical milestones

(1) Risk judge

Reflection: Built and measured. The risk judge combines a deterministic rule-based scorer with an LLM judge (weights 0.4 and 0.6) and feeds the combined score to the T-MDP policy. Measurement reversed one of our assumptions: the LLM judge is better calibrated than the trained classifier on every independent subset (expected calibration error 0.066 vs 0.345; false-positive rate on hand-written benign admin commands 5.3% vs 100% at p* = 0.40), and the combined judge corrects all rule-only errors on the tool-use scenarios.
Replanning: Minor. Evaluate on verbatim SafeToolBench and Risky-Bench items rather than scenarios written in their style, and add multi-sample averaging to reduce single-pass sampling noise (measured refusal or parse-failure rate 0.55%).

(2) Tool-use agent

Reflection: Partially complete. A LangChain tool-use agent runs the full workflow from the proposal (history parser, context builder, rule-based scorer plus LLM judge, combined risk score, T-MDP verdict) with a sandboxed search tool. On 40 scenarios the combined judge executed zero risky actions and blocked zero safe ones, versus 4 missed and 3 over-blocked for the rule-based scorer alone. Validation of final answers against dataset ground truth is not yet done; we currently score gate decisions, not answer correctness.
Replanning: Either connect the agent to a reasoning dataset and score answer correctness with search grounding, or scope this milestone to the safety-gate demonstration and list answer validation as future work. Given the Aug. 9 deadline we recommend the scoped version.

(3) Command-line agent

Reflection: The most complete leg: the rule-based anomaly detector, trained classifier, and T-MDP gate run end to end on held-out security logs, and we added evaluations on two independent corpora. Correcting labeling errors (438 of 618 malicious training events were VirtualBox housekeeping) revealed that the trained classifier is behaviorally identical to a 21-process whitelist (100% agreement on all 8,410 held-out events and on all 1,120 events of an independently collected attack-sample corpus, 99.95% on real enterprise telemetry from DARPA OpTC), and it flags 43% of genuinely benign enterprise events as malicious. So the rule-based detector works, but the learned layer adds no measurable value beyond process names, and the false-positive rate is the main deployment obstacle. This leg is offline log replay; no live LLM executes commands.
Replanning: Needed. Move to a content-based labeling rule so the model can learn more than process names, score the OpTC attack window to measure real-world detection (benign window is done), and optionally connect a live LLM agent to the gate instead of replay.

3. Next steps

Given these progresses we have made in the past weeks, the remaining work before the Aug. 9 report is: (1) score the OpTC attack window to complete the real-world evaluation; (2) evaluate the risk judge and tool-use agent on verbatim benchmark items so results are comparable to published work; (3) close or formally scope out the answer-correctness validation for the tool-use agent; (4) implement the horizon-dependent risk distribution; and (5) write the final report, anchored on the two results that survive scrutiny (the cost-derived T-MDP policy with its defer band, and the file-deletion significance result), with the security classifier presented honestly as equivalent to a process whitelist and its false-positive rate as the open problem.
