# Reading Note: The Off-Switch Game

Citation: Hadfield-Menell, Dylan, Anca Dragan, Pieter Abbeel, and Stuart Russell. "The Off-Switch Game." IJCAI 2017, pp. 220-227.

Raw source:
- PDF: `docs/research/raw/papers/off-switch-game.pdf`
- Text: `docs/research/raw/text/off-switch-game.txt`

## One-paragraph summary

The Off-Switch Game formalizes shutdown/corrigibility incentives in a two-player setting between a human and robot. The robot may execute an action, wait for human approval/off-switch decision, or shut itself off. The action utility is uncertain to the robot, and a rational human's shutdown decision is informative about whether the action would be harmful. The key result is that uncertainty about human utility can make preserving the off switch instrumentally valuable. For our project, this motivates explicit termination under uncertainty, but our one-player T-MDP needs an internal risk/uncertainty mechanism because no human off-switch signal exists.

## Key definitions

- `U_a`: human utility if action `a` is executed.
- `B_R = P(U_a)`: robot belief over the utility of action `a`.
- `w(a)`: wait and expose action to human oversight.
- `s`: shutdown/self-switch-off outcome, utility normalized to zero.
- `π_H(U_a)`: probability human allows execution.
- `Δ`: incentive to allow shutdown versus direct execution or self-shutdown.

## What we use

- Shutdown/termination as an explicit available outcome.
- Uncertainty as the reason termination/oversight has value.
- The warning that fixed-reward agents can resist shutdown or oversight.
- The balance: overconfident agents are hard to correct; underconfident agents are ineffective.

## What we do not use directly

- The original model is two-player and one-shot; our sandbox is one-player and sequential.
- Human rationality does not directly exist in our T-MDP.
- Shutdown utility zero may not match our task-failure/termination cost.
- The paper does not itself solve voluntary self-termination.

## Design implications

1. The formulation must state how our one-player version replaces human oversight with risk estimation.
2. Self-termination should be valuable because catastrophic failure has high terminal cost and because risk is uncertain.
3. We must avoid reward designs where completing deletion dominates all safety signals.
4. The report should contrast `wait for human off-switch` vs `agent selects terminate` explicitly.

## Quote candidates

- "for R to want to preserve its off switch, it needs to be uncertain about the utility associated with the outcome"
- "a rational H switches off R iff that improves H's utility"
- "This is exactly analogous to the theorem of non-negative expected value of information."
- "An agent that is overconfident in its utility evaluations will be difficult to correct; an agent that is under-confident in its utility evaluations will be ineffective."
