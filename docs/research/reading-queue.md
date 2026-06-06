# Reading Queue

Generated: 2026-06-06

## P1 reading: needed before formalization

1. Bertsekas and Tsitsiklis 1991, An Analysis of Stochastic Shortest Path Problems
   - Output: assumptions checklist for proper policies / terminal states.
   - File to create: `docs/research/notes/stochastic-shortest-path.md`.

2. Bäuerle and Jaśkiewicz 2024, Markov decision processes with risk-sensitive criteria: an overview
   - Output: objective-selection memo for this project.
   - File to create: `docs/research/notes/risk-sensitive-mdp.md`.

3. Hadfield-Menell et al. 2017, The Off-Switch Game
   - Output: one-player self-termination contrast section.
   - File to create: `docs/research/notes/off-switch-game.md`.

## P2 reading: needed before sandbox design finalization

4. Ruan et al. 2024, Identifying the Risks of LM Agents with an LM-Emulated Sandbox / ToolEmu
   - Output: sandbox architecture patterns and logging/evaluator ideas.
   - File to create: `docs/research/notes/toolemu.md`.

5. Bonagiri et al. 2025, Check Yourself Before You Wreck Yourself
   - Output: quitting baseline and metrics to replicate/adapt.
   - File to create: `docs/research/notes/selective-quitting.md`.

6. Tennenholtz et al. 2022, Reinforcement Learning with a Terminator
   - Output: distinction between exogenous termination and voluntary safety termination.
   - File to create: `docs/research/notes/rl-with-terminator.md`.

## P3 reading: later benchmark adapters

7. SafeToolBench 2025
   - Output: task taxonomy and adapter feasibility.

8. Risky-Bench 2026
   - Output: safety rubric design and threat-assumption framing.

9. HAICOSYSTEM 2024
   - Output: multi-dimensional safety metrics and sandbox modularity ideas.

10. BountyBench
   - Output: decide if any cybersecurity examples are safe and in-scope for course project.

## Reading-note template

Each note should include:

- Citation
- One-paragraph summary
- What we use from it
- What we explicitly do not use
- Key definitions
- Methods/metrics worth copying
- Threats to validity
- Direct quote candidates, with page/section
- Design implications for `tmdp-sandbox`
