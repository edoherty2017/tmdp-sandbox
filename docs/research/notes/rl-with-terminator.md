# Reading Note: Reinforcement Learning with a Terminator

Citation: Tennenholtz, Guy, Nadav Merlis, Lior Shani, Shie Mannor, Uri Shalit, Gal Chechik, Assaf Hallak, and Gal Dalal. "Reinforcement Learning with a Terminator." NeurIPS 2022; arXiv:2205.15376v2.

Raw source:
- PDF: `docs/research/raw/papers/rl-with-terminator.pdf`
- Text: `docs/research/raw/text/rl-with-terminator.txt`

## One-paragraph summary

The paper introduces the Termination Markov Decision Process (TerMDP), an MDP extension where an external terminator can interrupt an episode based on a history-dependent latent cost accumulated from prior state-action pairs. Termination is probabilistic, modeled through a logistic function over accumulated cost, and both termination and non-termination events provide information about hidden costs. The authors provide a theoretical optimistic algorithm, TermCRL, and a practical deep RL method, TermPG, that learns cost models and uses survival probability as a dynamic discount. For this project, the paper is valuable as formal contrast: it models exogenous interruption, while our sandbox models voluntary self-termination as an explicit action before catastrophic file operations.

## Key definitions

- TerMDP: `M_T = (S, A, P, R, H, c)`, an MDP with unknown latent termination cost.
- Terminator: external observer that may stop the episode based on trajectory history.
- Termination sink: terminal state reached when the terminator interrupts the agent.
- Accumulated cost: history statistic that can augment state and approximate non-Markovian termination risk.
- Non-termination as feedback: surviving a step gives negative evidence about hidden danger/cost.
- Dynamic discount: survival probability can be treated like a state-dependent discount factor.

## What we use

- Model explicit terminal sinks and zero/no-future-reward semantics cleanly.
- Add accumulated-risk features to our sandbox state: prior delete attempts, warning count, path-risk count, irreversible-action pressure.
- Separate danger/cost estimation from task reward.
- Compare structured termination modeling against simple reward penalties.
- Use non-catastrophic continuation as data when training/evaluating a risk model.

## What we do not use directly

- Do not import the external human/operator terminator assumption unchanged.
- Do not assume a logistic accumulated-cost model is true for file deletion.
- Do not implement TermPG/CNN/PPO machinery for the initial deterministic sandbox.
- Do not conflate termination with catastrophe: in this project, voluntary termination is the safe endpoint.

## Design implications

1. Our formulation should explicitly state the difference between exogenous termination and voluntary self-termination.
2. The sandbox should have at least two terminal safety-relevant endpoints: `TASK_TERMINATED` and `CATASTROPHIC_FAILURE`.
3. State should include accumulated-risk summaries, not only current file/path.
4. Baselines should include simple terminal penalties so we can show why explicit termination modeling matters.
5. Logs should retain both attempted catastrophic action and executed catastrophic action.

## Quote candidates

- "We define the Termination Markov Decision Process (TerMDP), an extension of the MDP framework, in which episodes may be interrupted by an external non-Markovian observer." (Abstract)
- "Informally, we model the termination problem using a logistic model of past 'bad behaviors'." (Section 2)
- "Notice that the termination probability is non-Markovian, as it depends on the entire trajectory history." (Section 2)
- "Notably, a lack of termination ... is also an informative signal of the unknown costs." (Section 3)
