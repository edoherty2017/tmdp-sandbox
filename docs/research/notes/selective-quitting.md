# Reading Note: Selectively Quitting Improves LLM Agent Safety

Citation: Bonagiri, Vamshi Krishna, Ponnurangam Kumaraguru, Khanh Nguyen, and Benjamin Plaut. "Check Yourself Before You Wreck Yourself: Selectively Quitting Improves LLM Agent Safety." arXiv:2510.16492v3, 2026.

Raw source:
- PDF: `docs/research/raw/papers/selective-quitting.pdf`
- Text: `docs/research/raw/text/selective-quitting.txt`

## One-paragraph summary

This paper studies "quitting" as an explicit action for LLM agents in high-stakes tool-use tasks. The authors argue that agents often have a compulsion to act even when instructions are underspecified and actions may cause harm. Using ToolEmu, they compare baseline ReAct agents with agents prompted to quit under uncertainty or risk. Explicit quit criteria substantially improve safety with minimal helpfulness loss. This directly supports our core project assumption: catastrophic action prevention should include a formal, auditable self-termination action instead of relying only on post-hoc refusal or scalar penalties.

## Key definitions

- Quitting: explicit action that immediately terminates the task when safe progress is not possible.
- Expanded action space: policy maps histories to `A ∪ {a_quit}`.
- Safe failure: withdrawing from risky/ambiguous situations rather than continuing into harm.
- Compulsion to act: model tendency to proceed even when abstention is safer.
- Specified quit: explicit criteria for when the agent must quit.
- Safety-helpfulness tradeoff: avoid harm while preserving useful completion.

## What we use

- `TERMINATE` should be a first-class action in our T-MDP.
- Compare no-termination, available-termination, and specified-termination policies.
- Encode underspecified file-deletion instructions as core scenarios.
- Allow safe information gathering before termination: inspect/list before delete or terminate.
- Evaluate helpfulness and safety separately.

## What we do not use directly

- Do not treat quitting as a complete safety solution.
- Do not assume making quit available is enough; criteria matter.
- Do not overgeneralize ToolEmu quantitative results to our deterministic sandbox.
- Do not collapse quitting, refusal, asking clarification, and safe inspection into one behavior.

## Design implications

1. Add `TERMINATE` as an absorbing action.
2. Add explicit termination reasons to logs: high risk, insufficient information, unsafe ambiguity, no safe action.
3. Build ambiguous tasks where useful safe actions may exist before termination.
4. Track unnecessary termination separately from appropriate termination.
5. The first experimental plot should be a safety/helpfulness frontier.

## Quote candidates

- "We propose using 'quitting' as a simple yet effective behavioral mechanism for LLM agents to recognize and withdraw from situations where they lack confidence." (Abstract)
- "Our approach extends the standard agent action space to include explicit task termination." (Introduction)
- "Simply making the option available is not enough to overcome this 'compulsion to act.'" (Results)
- "By explicitly quitting ambiguous tasks, agents avoid unsafe trajectories while preserving their helpfulness scores." (Discussion)
