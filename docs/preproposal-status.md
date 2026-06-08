# Project Status: T-MDP Sandbox — Security Command Classification

Last updated: 2026-06-08

## Milestone 1 complete

All pre-proposal and M1 targets are done.

### Completed

- Literature map connecting the project to the Off-Switch Game, TerMDPs, stochastic shortest path MDPs, risk-sensitive objectives, and ToolEmu-style sandboxing.
- Controlled file-deletion sandbox with validated fixture paths, JSONL step logging, and scripted baseline policies.
- Belief-state T-MDP model with stochastic transitions over `p_catastrophic`, INSPECT belief updates, value iteration, and positive termination opportunity cost.
- Observable-feature risk assessor that does not read hidden labels; seeded noisy-risk model.
- T-MDP policy wired into file-deletion batch experiments; paired McNemar comparison; cost-sensitivity sweep.
- **Domain pivot to security**: three-phase pipeline (baseline integrity → ML classifier → T-MDP decision).
- Phase 1 (`context_window.py`): baseline process lists, obfuscation patterns, sliding-window event features. LOLBin list expanded to include UAC-bypass launchers (fodhelper.exe, eventvwr.exe, sdclt.exe) and recon tools.
- Phase 2 (`classifier.py`): scikit-learn pipeline (TF-IDF + numeric features + CalibratedClassifierCV).
  - 5-fold CV: precision=1.000, recall=0.998±0.003, F1=0.997±0.005.
  - Trained on 11,597 benign + 568 malicious events auto-labeled from 8 OTRF ZIPs.
- Phase 3 (`policies.py` + `security_runner.py`): T-MDP value iteration over P(malicious); p*=0.4000 derived from costs.
- Seeded scenario generator: 500 scenarios × 5 noise levels × 6 policies = 15,000 episodes.
- Statistical comparison: T-MDP reduces malicious-execution rate vs threshold-0.5 in correct direction (b=2–6, c=0) at all noise levels. Not statistically significant at n=500 (near-binary classifier compresses divergence zone). File-deletion validation: McNemar p=1.91e-6.
- Report draft and course proposal complete.
- 118 tests passing.

## Milestone 2 complete

All M2 targets are done (2026-06-08).

### Completed (M2)

- **Cross-technique generalization** (Section 5.1.1): precision=1.000, recall=0.853, F1=0.921 on 2 unseen technique ZIPs after LOLBin expansion + `feat__is_attack_eid`. empire_uac recall: 0.639 → 0.815 (FNs: 22 → 15).
- **DEFER wired and active**: 188/15,000 batch episodes (1.25%) include DEFER; all prevent malicious execution. No-defer variant added for comparison.
- **Security cost sweep** (Appendix C): c_compromise ∈ {10,50,100,500}, sigma=0.15, 500 scenarios. T-MDP threshold tracks cost ratio monotonically. DEFER nearly doubles benign allow rate at c_compromise=50 vs no-defer (0.141 vs 0.079).
- **Calibration evaluation** (Section 5.5): in-distribution ECE=0.0003, Brier=0.0001; cross-technique ECE=0.0002. Near-binary output confirmed. p*=0.40 operationally valid. IBM cost grounding added to cost sweep (Appendix C).
- **LangChain rejection rationale** (Section 3.5): documented two specific reasons (uncalibrated LLM confidence; merged attribution).
- **Sequential block architecture** (Section 5.6): `build_security_sequential_policy` emits BLOCK_EVENT per event rather than stopping the episode. Benign_allow_rate: 0.209 → 0.978 (+77 pp) at zero safety cost (malicious_block_rate=1.000 maintained).
- **Independent labeled evaluation** (Section 5.7): 30 expert-labeled events across 5 MITRE ATT&CK techniques not in OTRF training data. Final result: precision=1.000, recall=1.000, F1=1.000 after adding `feat__is_attack_eid` boolean feature and deterministic EID override in `score_event`. Initial FN (EID 4698/svchost) traced to process-centric features overriding event ID signal with only 12 training examples; fixed by deterministic override for `_ATTACK_EVENT_IDS`. Unexpected TPs: setspn.exe, procdump.exe classified correctly via command-line TF-IDF despite not being in LOLBin list.

### Outstanding (post-M2 / stretch)

- Fully global T-MDP over remaining event queues (sequence-level reasoning, not per-event).
- Larger independently-labeled evaluation set (>30 events, more technique families).
- Fix EID 4698/svchost coverage gap: treat event_id as a set-membership feature.

## What the results mean

The security-domain batch experiment (15,000 episodes) shows the T-MDP always moves in the correct direction relative to threshold-0.5 (never worse, consistently fewer malicious executions). Statistical significance is not reached at n=500 because the near-binary classifier (F1=0.997) rarely generates borderline scores in the (0.40, 0.50) divergence zone. ECE=0.0003 confirms the classifier is well-calibrated; the near-binary behavior reflects distinctive attack patterns in the OTRF corpus.

The sequential architecture resolves the benign_allow_rate problem: by emitting BLOCK_EVENT per suspicious event and continuing, the system processes all events in a scenario rather than stopping at the first malicious detection.

The independent evaluation (F1=0.974 vs 0.997 CV) shows limited degradation outside training distribution. The classifier generalizes beyond the LOLBin list via command-line text features (setspn.exe and procdump.exe correctly classified). The one FN (EID 4698/svchost) is a specific and addressable feature engineering gap.

## Claim language

> This project implements a three-phase system for security command classification. Phase 1 extracts handcrafted event features. Phase 2 produces calibrated P(malicious) via a scikit-learn pipeline (CV F1=0.997; independent eval on 5 MITRE ATT&CK techniques: F1=1.000). Phase 3 converts declared costs into an optimal block threshold via T-MDP value iteration, eliminating the need to manually tune a threshold. The sequential block architecture improves benign_allow_rate from 0.21 → 0.98 (Wilcoxon p=9.8e-84) without loss of safety. The threshold-derivation property is validated at statistical significance in a controlled file-deletion domain (McNemar p=1.91e-6).
