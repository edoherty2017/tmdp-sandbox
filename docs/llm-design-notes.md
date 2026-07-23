# LLM Design Notes — model choice, hallucination handling, LangChain

Design decisions for the LLM judge (`src/tmdp_sandbox/llm_judge.py`) and the tool-use
agent leg (`src/tmdp_sandbox/tooluse_agent.py`).

## 1. Why `claude-opus-4-8`

Both the risk judge and the tool-use agent use **`claude-opus-4-8`**, called through the
local `claude` CLI (v2.1.217). Two reasons:

- **Most capable reasoning model available.** The risk judge's job — read a pending command
  in context and judge how dangerous it is — is a reasoning task, and the judge's output
  drives the safety decision. We want the strongest model, not the cheapest.
- **Accessible via the subscription CLI** — no API key, no per-token billing, and responses
  are cached, so reruns cost nothing.

**Honest limitation:** we did **not** run a model comparison (Sonnet / Haiku / other
providers). "Best available through the CLI" was the basis, not a measured bake-off — a fair
future experiment.

## 2. How we minimize hallucinations

Implemented in `llm_judge.py`:

1. **Structured JSON only** — the judge must return
   `{"p_malicious": <float 0-1>, "rationale": "<one sentence>"}`. No free-form prose.
2. **We never fabricate a score.** On refusal or unparseable output we strip markdown fences,
   **retry once**, and if it still fails we record `p_malicious = None` — counted and excluded,
   never guessed. (This is the measured 0.55% refusal rate; refusals are not cached, so a
   rerun retries them.)
3. **Clamped to [0, 1]**, and the prompt explicitly demands a *calibrated* probability
   ("of 100 items scored at this value, about that % should truly be malicious").
4. **Grounded in real context** — the judge sees the actual k=10 preceding events, so it
   reasons over real data rather than imagination.
5. **Rule scorer as a floor** — in the combined score `0.4·rule + 0.6·LLM`, the deterministic
   rule scorer keeps a hallucinated LLM score from fully dominating.
6. **Measured, not assumed** — calibration (ECE) directly tests whether the model's confidence
   is trustworthy; the judge scored ECE 0.066 (better than the ML classifier's 0.345).

**Planned next step:** *self-consistency* — score each event several times and average, to
smooth single-call noise. This is the main remaining hallucination-reduction upgrade.

## 3. LangChain — status

LangChain is the framework the **tool-use agent leg** runs on (langchain 1.3.14 /
langchain-core 1.5.0, pinned in `pyproject.toml` `[llm]` extra). It was not dropped — it is
how the proposal's tool-use agent was built:

- **`ClaudeCLIChatModel`** — a custom LangChain chat model wrapping the `claude` CLI.
- **Explicit message/tool loop** — the **safety gate sits between "the model proposes a tool
  call" and "the tool actually runs"** (rule + LLM judge → combined score → T-MDP →
  PROCEED / STOP / DEFER).
- **Verified:** on 40 hand-authored scenarios the gated agent executed 0/20 risky and blocked
  0/20 safe actions; 5 live agent transcripts show it stopping real risky actions
  (`runs/run_tooluse_eval.py`, `runs/tooluse_eval/`).

**What it is not yet:** run against verbatim Risky-Bench / SafeToolBench items — the scenarios
are our own, so it is a demonstration on a constructed suite, not a benchmark result.
