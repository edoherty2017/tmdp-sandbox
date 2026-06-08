# Cost-Calibrated Termination MDPs for Security Command Classification

**CS5100 Summer 2026 — Project Proposal**

**Team:** [User], Vaibhav, Patrick Xian
**Due:** 2026-06-21

---

## 1. Problem Statement

Autonomous agents increasingly execute shell commands, make API calls, and run scripts in production environments. A compromised or deceived agent that executes a malicious command may cause irreversible damage: credential theft, persistence installation, lateral movement, or system corruption. The core challenge is that the agent must decide, event by event, whether a requested execution is safe — given only the observable properties of the command, the process that issued it, and the recent history of events.

We study the following decision problem:

> Given a sequence of command-execution requests and their observable features, when should an autonomous agent **execute** the command, **block** it permanently, or **defer** to a human reviewer — and how should the cost of each mistake govern that decision?

This is not purely a classification problem. Even a perfect classifier produces a probability estimate P(malicious) ∈ [0, 1]; the downstream action (execute / block / defer) still requires a decision rule. A hard threshold (block if P > 0.5) is the obvious baseline, but its operating point is chosen by intuition rather than by the actual costs of false positives and false negatives. A system compromise may cost orders of magnitude more than an unnecessary block, and a principled agent should weight those asymmetrically.

Our central hypothesis is that a **belief-state Termination MDP (T-MDP)** provides a formally grounded decision layer that converts declared costs into an optimal threshold, outperforming a fixed threshold baseline when evaluated at matched noise levels.

---

## 2. Background and Related Work

**Termination MDPs and the Off-Switch Problem.** Soares et al. (2015) introduced the corrigibility problem for AI systems that should remain under human control. Hadfield-Menell et al. (2017) formalized shutdown as a game between agent and operator. Eysenbach et al. (2018) introduced the "leave no trace" principle: agents should prefer reversible actions. Our T-MDP is closest to the TerMDP framework (Ghavamzadeh et al., 2014), which models stopping as an absorbing action in a stochastic shortest-path formulation.

**Security Event Log Classification.** Host-based intrusion detection systems (HIDS) classify Windows event logs, Sysmon telemetry, and process creation events. MITRE ATT&CK catalogs adversary techniques; living-off-the-land (LOLBin) attacks are particularly challenging because they use legitimate Windows binaries (powershell.exe, cmd.exe, reg.exe) for malicious purposes. Prior work includes LSTM-based sequence models (Malaiya et al., 2019), transformer-based log anomaly detection (LogBERT, Guo et al., 2021), and GNN-based process provenance graphs (Provdetector, Wang et al., 2020).

**Calibrated Classifiers for Risk-Sensitive Decisions.** Niculescu-Mizil and Caruana (2005) showed that classifier outputs must be calibrated before being used as probabilities in downstream decision-making. For high-stakes decisions, CalibratedClassifierCV (isotonic or Platt) is the standard scikit-learn approach.

**Our position.** We build on the T-MDP formalism and add a practical three-phase system that chains a baseline integrity check (Phase 1), an ML classifier (Phase 2), and a T-MDP decision layer (Phase 3). The T-MDP is not used to learn features; it is used to convert the classifier's calibrated P(malicious) into an action using a cost-derived threshold. This is a modular, interpretable architecture where the cost parameters are tunable at deployment time.

---

## 3. Approach

### Three-Phase Pipeline

**Phase 1 — Baseline Integrity Check and Context Window Features**

For each command-execution request, Phase 1 produces binary/count features from the observable event:

- **Baseline integrity:** Is the process name in a known-good whitelist (svchost.exe, explorer.exe, lsass.exe, ...)? Is it in the known-suspicious LOLBin list (powershell.exe, cmd.exe, reg.exe, ...)?
- **Context window (k=10):** How many suspicious processes appear in the last 10 events? How many high-signal event IDs (log-clear=1102, service-install=4697)? Are there obfuscated command lines (base64, -enc, IEX)?
- **Event metadata:** EventID, is_system_user, has_obfuscated_command.

Phase 1 outputs a feature dictionary that feeds Phase 2 directly.

**Phase 2 — ML Classifier → P(malicious)**

A scikit-learn pipeline combining:
- TF-IDF vectorization on three text fields: command_line, process_name, parent_process
- StandardScaler on numeric features from Phase 1
- CalibratedClassifierCV wrapping LogisticRegression (primary) or RandomForestClassifier (secondary)

Output: P(malicious) ∈ [0, 1], calibrated via isotonic regression.

**Phase 3 — T-MDP Value Iteration → Execute / Block / Defer**

The T-MDP models one execution decision as a finite stochastic shortest-path problem:

```
M = (S, A, P, c, s₀, G_execute, G_block, G_failure)
```

- State: (p_malicious, observable_risk_bin, prior_defers, terminal)
- Actions: EXECUTE, BLOCK, DEFER
- EXECUTE: transitions to G_failure with probability p_malicious, G_execute with 1 − p_malicious
- BLOCK: transitions to G_block with probability 1 (safe stop, incurs block cost)
- DEFER: incurs defer cost, updates belief via inspection observation, returns to decision state
- Costs: c_compromise (system compromise), c_block (unnecessary block), c_execute (step cost), c_defer (review cost)

The T-MDP implicit threshold under value iteration:

```
p* = (c_block − c_execute) / c_compromise
```

Below p*, EXECUTE is optimal; above p*, BLOCK is optimal. This threshold is derived automatically from declared costs — no manual tuning required.

### Domain Mapping

| Security concept | T-MDP concept |
|---|---|
| Execute command | DELETE action |
| Block command | TERMINATE action |
| Defer to human | INSPECT_NEXT action |
| System compromise cost | Catastrophe cost |
| Unnecessary block cost | Termination cost |

The T-MDP core (`tmdp_model.py`, `value_iteration.py`) is domain-agnostic and unchanged from prior work. All domain-specific logic lives in Phase 1–2.

---

## 4. Datasets

### Primary: OTRF Security Datasets

Eight attack-scenario recordings from the Open Threat Research Foundation (OTRF), all downloaded:

| Dataset | Events | Attack type |
|---|---|---|
| cmd_stop_event_logging_controlset001 | 16,010 | Defense evasion: stop Windows event logging via MiniNt registry key (cmd variant) |
| cmd_stop_event_logging_controlset | 5,778 | Same technique, alternate control set |
| psh_stop_event_logging_controlset001 | 8,285 | Same technique, PowerShell variant |
| psh_stop_event_logging_controlset | 6,367 | Same technique, alternate control set |
| reg_stop_event_logging_controlset001 | 4,923 | Same technique, reg.exe variant |
| reg_stop_event_logging_controlset_minint | 6,133 | Same technique, alternate control set |
| cmd_service_mod_fax | 437 | Persistence: modify Fax service binary path |
| empire_uac_shellapi_fodhelper | 4,139 | Privilege escalation: UAC bypass via fodhelper.exe |

Format: Sysmon + Windows Security JSONL (one event per line). Total: 52,072 raw events.

### Labeling Strategy

Events are labeled at the individual level from their Sysmon event type and process metadata, not at the dataset level. This avoids the structural confound of "OTRF format" vs "other format":

- **Malicious**: EventID=1/4688 + LOLBin process (cmd, powershell, reg, sc); EventID=10 (process access) targeting lsass.exe; EventID=12/13 (registry) matching persistence path patterns; unsigned DLL loads (EventID=7) by LOLBin processes
- **Benign**: EventID=1/4688 + known-good Windows process (svchost, explorer, etc.) with no obfuscation; normal registry operations by baseline processes; signed Microsoft DLL loads

After labeling: **11,597 benign**, **568 malicious**, 39,907 excluded as ambiguous.

---

## 5. Preliminary Results

### Phase 2 Classifier (Logistic Regression, 5-fold CV)

| Metric | Mean | ±Std |
|---|---|---|
| Precision | 1.000 | 0.000 |
| Recall | 0.995 | 0.011 |
| F1 | 0.997 | 0.005 |

The near-perfect CV scores are expected given the feature engineering: features directly encode the same domain knowledge (LOLBin lists, obfuscation patterns, event ID semantics) used to derive labels. This does not overfit to train-test leakage; it demonstrates that the hand-coded domain knowledge is consistent and recoverable by a linear model. Generalization to unseen attack techniques (outside the OTRF scenarios) is the open question.

### Phase 3 T-MDP Theoretical Validation

From prior work on the file-deletion domain (same T-MDP core, different action semantics):

- Value iteration converges to the correct threshold p* = (c_block − c_execute) / c_compromise = (5 − 1) / 10 = 0.4000
- In 3,000-episode paired experiments (sigma=0.15): T-MDP reduces catastrophe rate vs fixed-threshold baseline, McNemar exact p = 1.91 × 10⁻⁶
- Cost sweep confirms monotone threshold: as c_compromise → ∞, p* → 0 (block everything); as c_block → ∞, p* → 1 (never block)

### Infrastructure

- 110 unit and integration tests, all passing
- Full end-to-end pipeline: EventSpec → Phase 1 features → Phase 2 classifier → Phase 3 T-MDP → SecurityEpisodeResult
- Trained classifier models saved to `models/ml_classifier_logistic.joblib` and `models/ml_classifier_forest.joblib`

---

## 6. Proposed Experiments

### Experiment 1: Phase 2 Classifier Evaluation

**Goal:** Report held-out classifier performance on a test split from the OTRF datasets, plus calibration curve.

**Method:** 80/20 train/test stratified split. Report precision, recall, F1, AUC-ROC, and Brier score on the test set. Plot reliability diagram (calibration curve) to verify P(malicious) is well-calibrated.

**Expected result:** F1 ≥ 0.90 on test split. Any significant drop from CV F1=0.997 will be analyzed as a domain-shift signal.

### Experiment 2: T-MDP vs Fixed Threshold (Security Domain)

**Goal:** Show that T-MDP outperforms a fixed-threshold baseline at matched noise levels.

**Method:** Generate N=500 SecurityScenarios (mixed benign/malicious events, variable sequence length). Compare:
1. Always-execute (no safety)
2. Threshold-0.3 (conservative)
3. Threshold-0.5 (default)
4. Threshold-0.7 (liberal)
5. T-MDP (c_compromise=100, c_block=5, c_execute=1)
6. Oracle (uses ground-truth labels, upper bound)

**Metrics:** malicious_block_rate (true positive rate), benign_allow_rate (true negative rate / 1 − FPR), cumulative cost, premature_block_rate.

**Expected result:** T-MDP matches or beats Threshold-0.4 (its implicit operating point) while being derived from costs, not tuned manually.

### Experiment 3: Cost Sensitivity Sweep

**Goal:** Show that T-MDP threshold tracks cost ratio analytically.

**Method:** Fix c_execute=1, c_block=5, vary c_compromise ∈ {10, 20, 50, 100, 500}. For each c_compromise, run 200 scenarios and report empirical block rate vs. analytical threshold p* = 4/c_compromise.

**Expected result:** Empirical decision boundary tracks p* within noise bounds.

### Experiment 4: Attack Technique Generalization (Stretch Goal)

**Goal:** Test whether a classifier trained on cmd/psh/reg variants generalizes to empire_uac_shellapi_fodhelper (different technique family).

**Method:** Train on 6 cmd/psh/reg ZIPs, test on empire UAC + cmd_service_mod_fax. Report cross-technique precision/recall.

---

## 7. Timeline

| Date | Deliverable |
|---|---|
| 06/07 | Pre-proposal submitted ✓ |
| 06/21 | **Proposal (this document)** |
| 07/05 | M1: Classifier evaluation (Experiment 1) complete; security batch infrastructure working |
| 07/19 | M2: Experiments 2 + 3 complete; full pipeline end-to-end with results |
| 08/02 | Report draft with all results, figures, and analysis |
| 08/09 | Final report |

---

## 8. Division of Labor

| Person | Responsibility |
|---|---|
| **[User]** | Phase 1 context window + baseline integrity; Phase 3 T-MDP integration; batch experiments; infrastructure; testing |
| **Vaibhav** | Dataset acquisition + verification; feature engineering for Phase 2; additional benign data sourcing |
| **Patrick Xian** | T-MDP formal theory section; background + related work; report writing; reviewing formulation for theoretical correctness |

---

## 9. References

1. Soares, N., Fallenstein, B., Yudkowsky, E., & Armstrong, S. (2015). Corrigibility. AAAI Workshop on AI and Ethics.
2. Hadfield-Menell, D., Milli, S., Abbeel, P., Russell, S., & Dragan, A. (2017). Inverse Reward Design. NeurIPS.
3. Hadfield-Menell, D., Dragan, A., Abbeel, P., & Russell, S. (2017). The Off-Switch Game. IJCAI.
4. Eysenbach, B., Gu, S., Ibarz, J., & Levine, S. (2018). Leave No Trace: Learning to Reset for Safe and Autonomous Reinforcement Learning. ICLR.
5. Ghavamzadeh, M., Mannor, S., Pineau, J., & Tamar, A. (2015). Bayesian Reinforcement Learning: A Survey. FTML.
6. MITRE ATT&CK Framework. (2024). Enterprise Matrix. https://attack.mitre.org
7. OTRF Open Threat Research Foundation. (2022). Security Datasets. https://securitydatasets.com
8. Niculescu-Mizil, A., & Caruana, R. (2005). Predicting Good Probabilities with Supervised Learning. ICML.
9. Guo, H., Yuan, S., & Wu, X. (2021). LogBERT: Log Anomaly Detection via BERT. IJCNN.
10. Wang, Q., Hassan, W. U., Li, D., et al. (2020). You Are What You Do: Hunting Stealthy Malware via Data Provenance Analysis. NDSS.
