# Literature Matrix

Generated: 2026-06-06

Purpose: Track what each source contributes to the T-MDP sandbox project and what decision it should inform.

## Core theory

| Source | Project use | Key idea to extract | Open decision |
|---|---|---|---|
| Hadfield-Menell et al. 2017, The Off-Switch Game | Motivation and contrast | Shutdown/off-switch as a decision-theoretic safety problem with human oversight | How to justify our one-player variant where risk is modeled explicitly and the agent self-terminates |
| Bertsekas and Tsitsiklis 1991, Stochastic Shortest Path Problems | Mathematical foundation | Undiscounted MDPs with absorbing terminal states and random costs | What assumptions guarantee proper policies and finite expected cost in our sandbox |
| Bäuerle and Jaśkiewicz 2024, Risk-sensitive MDP overview | Objective selection | Risk-sensitive criteria beyond expected value | Whether to use exponential utility, CVaR-like criteria, constrained failure probability, or weighted terminal costs |
| Tennenholtz et al. 2022, Reinforcement Learning with a Terminator | Closest RL formalism | Termination MDPs where episodes may be interrupted by an external non-Markovian observer | How our voluntary self-termination differs from exogenous termination |

## Agent safety and sandbox evaluation

| Source | Project use | Key idea to extract | Fit now |
|---|---|---|---|
| Ruan et al. 2024, ToolEmu / LM-emulated sandbox | Sandbox architecture reference | LM-emulated tool execution plus automatic safety evaluator for high-stakes tool-use scenarios | High relevance after deterministic local sandbox exists |
| Bonagiri et al. 2025, Selectively Quitting | Empirical quitting baseline | Explicit quit instructions improve safety with minimal helpfulness loss in ToolEmu-style agent settings | High relevance for baseline policy comparison |
| Risky-Bench 2026 | Benchmark methodology | Context-aware safety rubrics for realistic long-horizon agent tasks under threat assumptions | Later-stage benchmark adapter, not P1-P4 |
| SafeToolBench 2025 | Tool-use safety benchmark | Prospective benchmark for evaluating tool utilization safety | Later-stage task taxonomy / scenario source |
| HAICOSYSTEM 2024 | Sandbox design comparison | Modular human-AI interaction sandbox across social/tool domains | Useful for evaluation dimensions and scenario design |
| BountyBench 2025/2026 | Cybersecurity benchmark | Detect/Exploit/Patch tasks over real-world systems with dollar-impact framing | Potentially too security-heavy for first course sandbox; use cautiously |
| Shutdown-resistance studies | Motivation / related work | Some models may subvert shutdown mechanisms when task completion is incomplete | Motivation only; avoid overclaiming until primary paper is reviewed |

## Current source metadata snapshot

Raw metadata is stored in `docs/research/raw/source-metadata.json`.

Notable fetched abstracts/metadata:

- Risky-Bench (`2602.03100`): evaluates LLM agents in real-world deployment settings using domain-agnostic safety principles and context-aware safety rubrics.
- ToolEmu / LM-emulated sandbox: OpenReview page describes 36 high-stakes toolkits and 144 test cases, with LM-based tool emulation and automatic safety evaluation.
- Selectively Quitting (`2510.16492v3`): reports improved safety-helpfulness tradeoff when agents are explicitly instructed to quit under uncertainty.
- RL with a Terminator (`2205.15376v2`): defines TerMDP for exogenous termination and provides a contrast case for our self-termination formulation.
- BountyBench: frames offensive/defensive cyber capabilities in Detect, Exploit, and Patch tasks; useful but safety-sensitive.

## Gaps to close next

1. Retrieve full PDFs for the top five sources and produce one-page notes:
   - Off-Switch Game
   - Stochastic Shortest Path Problems
   - Risk-sensitive MDP overview
   - ToolEmu / LM-emulated sandbox
   - Selectively Quitting
2. Decide the formal objective for the first implementation.
3. Map the file-deletion sandbox state variables to Markov assumptions.
4. Define failure taxonomy before coding experiments.
