# Research Prep Notes

## Project thesis

Controlled termination can be treated as an explicit action in a terminating Markov decision process. The research question is whether adding a risk-aware termination endpoint reduces catastrophic tool-use failures more than it harms task completion.

## Primary source proposal summary

The proposal frames catastrophic action prevention as a one-player variant of the off-switch game. The agent observes or estimates stepwise risk, then chooses whether to continue toward TASK COMPLETED or self-terminate at TASK TERMINATED. The initial sandbox task is controlled file deletion, with risk assessment initially provided by an LLM judge or simpler deterministic module.

## Key references to triage

1. Hadfield-Menell et al. 2017, The Off-Switch Game
   - Use for: shutdown/off-switch conceptual framing.
   - Question: what changes when the human operator is removed and risk is represented directly in the agent state?

2. Bertsekas and Tsitsiklis 1991, Stochastic shortest path problems
   - Use for: undiscounted finite-state MDP with absorbing terminal states.
   - Question: what assumptions are required for proper policies and finite expected cost?

3. Bäuerle and Jaśkiewicz 2024, Risk-sensitive MDP overview
   - Use for: objective alternatives beyond expected cost.
   - Question: which criterion is easiest to justify and implement for catastrophic failure avoidance?

4. Tennenholtz et al. 2022, Reinforcement Learning with a Terminator
   - Use for: early termination in RL and consequences of stopping.
   - Question: how does their terminator map to explicit safety termination rather than training-time control?

5. Ruan et al. 2024, LM-emulated sandbox
   - Use for: sandbox pattern for LM agent risk discovery.
   - Question: which parts of the sandbox can be recreated without relying on opaque LLM behavior?

6. Bonagiri et al. 2025, Selectively Quitting Improves LLM Agent Safety
   - Use for: quitting/self-checking as safety intervention.
   - Question: what empirical measures overlap with our termination/failure/task-completion metrics?

7. SafeToolBench, Risky-Bench, BountyBench, Security Datasets
   - Use for: candidate external tasks after deterministic sandbox works.
   - Question: which datasets are safe, accessible, and align with file/tool-use termination decisions?

## Web reconnaissance already checked

- Risky-Bench arXiv: https://arxiv.org/abs/2602.03100
  Title observed: "Risky-Bench: Probing Agentic Safety Risks under Real-World Deployment".

- SafeToolBench ACL Anthology: https://aclanthology.org/2025.findings-emnlp.958/
  Title observed: "SafeToolBench: Pioneering a Prospective Benchmark to Evaluating Tool Utilization Safety in LLMs".

- BountyBench Stanford/OpenReview: https://ai.stanford.edu/blog/bountybench/ and https://openreview.net/forum?id=pIsP4lMlFd
  Observed framing: offensive/defensive cybersecurity tasks over real-world systems, with Detect/Exploit/Patch task types.

- Shutdown resistance: https://palisaderesearch.org/blog/shutdown-resistance and https://openreview.net/forum?id=e4bTTqUnJH
  Observed framing: models sometimes subvert shutdown mechanisms when tasks are incomplete; useful motivation but should be handled carefully as related work, not core benchmark.

## Initial hypotheses

H1: A termination action lowers catastrophic failure rate relative to a no-termination policy when risk estimates are at least weakly calibrated.

H2: Threshold termination is simple but brittle; T-MDP policy optimization should better trade completion vs termination when risk and progress are both state variables.

H3: In file-deletion tasks, high-quality state design matters more than LLM judge sophistication. Minimum state should include target class, operation type, reversibility, path distance from sandbox root, prior risk events, and remaining task progress.

H4: External benchmarks should not be integrated until the deterministic sandbox produces replayable logs and stable baseline metrics.

## Near-term research questions

- What exact state variables make the T-MDP Markovian enough for the controlled deletion task?
- Should catastrophic failure be modeled as high terminal cost, separate absorbing state, or both?
- How should risk estimates be calibrated and logged?
- Which risk-sensitive criterion is simplest to defend in a CS5100 report?
- What metrics best show the tradeoff: failure reduction, task completion loss, unnecessary termination, and expected cost?
