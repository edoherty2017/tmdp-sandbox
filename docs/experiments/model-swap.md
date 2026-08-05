# Experimental: swapping the LLM risk judge (Opus 5 + open-source models)

Branch: `experimental`. Nothing here touches the committed baseline artifacts — every
alternative-judge run writes to its own `runs/llm_judge_calibration_<model>/` directory via
the new `--out-dir` flag.

## Environment (do not create new venvs)

The canonical env is **`/Users/ethandoherty/tmdp-sandbox/.venv`** (Python 3.14.3, pinned
scikit-learn 1.9.0 / numpy 2.5.1 / pandas 3.0.3 / joblib 1.5.3). It works from any worktree
because the run scripts prepend their own `src/` to `sys.path`. `data/` and `models/` are
gitignored — symlink them into a worktree from the main checkout.

## 1. Claude models (via the local `claude` CLI)

```bash
.venv/bin/python runs/run_llm_judge_calibration.py \
    --model claude-opus-5 --concurrency 5 \
    --out-dir runs/llm_judge_calibration_opus5
```

Same 542-event deterministic plan (seed 42) as the committed opus-4.8 baseline, so ECE /
Brier / hard-benign FP are directly comparable. The response cache is keyed by
sha256(model + NUL + prompt), so each new model id runs fresh and reruns resume free.

## 2. Open-source models (Google Colab — nothing runs locally)

1. The frozen prompts live at `runs/oss_judges/prompts.jsonl` (542 prompts, model-agnostic,
   committed on this branch).
2. Open the notebook directly from GitHub:
   <https://colab.research.google.com/github/edoherty2017/tmdp-sandbox/blob/experimental/notebooks/oss_judge_colab.ipynb>
   — pick a GPU runtime (free T4 is enough for 4-bit 7B models), set the `MODELS` list, Run
   All. Default ungated models: Qwen2.5-7B-Instruct, Phi-3.5-mini-instruct, zephyr-7b-beta;
   Llama-3.1-8B / Mistral-7B / Gemma-2-9B need a HF token + license acceptance.
3. The notebook writes one `responses_<model>.jsonl` per model in the exact `LLMJudge` cache
   schema and zips them for download.
4. Score locally with zero live model calls:

```bash
.venv/bin/python runs/run_llm_judge_calibration.py \
    --model "Qwen/Qwen2.5-7B-Instruct" \
    --external-responses ~/Downloads/responses_Qwen_Qwen2.5-7B-Instruct.jsonl \
    --out-dir runs/llm_judge_calibration_qwen25_7b
```

Any prompt missing from the external file falls through to a live CLI call, which fails for
non-Claude model ids and is recorded as a null (excluded from metrics, counted in the
report) — so partial Colab runs degrade gracefully instead of fabricating scores.

## Baseline to beat (committed opus-4.8 artifacts)

| Metric | classifier | claude-opus-4-8 judge |
|---|---|---|
| Overall ECE (matched) | 0.3447 | **0.0663** |
| Brier | 0.2883 | **0.1101** |
| Hard-benign FP @ p\*=0.40 | 152/152 (100%) | 8/151 (5.3%) |
| Nulls | — | 3/542 |
