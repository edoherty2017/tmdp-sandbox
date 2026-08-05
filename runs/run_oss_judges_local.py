"""Run open-source LLM risk judges locally on Apple silicon (MLX).

Scores the frozen 542-event prompt set (runs/oss_judges/prompts.jsonl) with
4-bit MLX community builds of open-source instruct models and writes one
``responses_<model>.jsonl`` per model in the exact ``LLMJudge`` cache schema
({key, model, p_malicious, rationale, raw_response},
key = sha256(model + NUL + prompt)), so each file can be scored with zero
live model calls:

    .venv/bin/python runs/run_llm_judge_calibration.py \
        --model mlx-community/Qwen2.5-7B-Instruct-4bit \
        --external-responses runs/oss_judges/responses_mlx-community_Qwen2.5-7B-Instruct-4bit.jsonl \
        --out-dir runs/llm_judge_calibration_qwen25_7b

Greedy decoding (temperature 0), one model resident at a time. Resumable:
existing per-model output files are loaded first and already-scored keys are
skipped, so an interrupted run continues where it left off.

Usage:
    python runs/run_oss_judges_local.py [--models m1 m2 ...] [--limit N]
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import re
import time
from pathlib import Path

DEFAULT_MODELS = [
    "mlx-community/Qwen2.5-7B-Instruct-4bit",
    "mlx-community/Phi-3.5-mini-instruct-4bit",
    "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit",
    "mlx-community/Mistral-7B-Instruct-v0.3-4bit",
]

HERE = Path(__file__).parent
PROMPTS_PATH = HERE / "oss_judges" / "prompts.jsonl"
OUT_DIR = HERE / "oss_judges"

JSON_RE = re.compile(r"\{[^{}]*\"p_malicious\"[^{}]*\}", re.DOTALL)
MAX_TOKENS = 224


def parse_reply(text: str) -> tuple[float | None, str]:
    """Mirror LLMJudge parsing: find the JSON object, clamp p to [0, 1]."""
    m = JSON_RE.search(text)
    if not m:
        return None, "unparseable model reply"
    try:
        obj = json.loads(m.group(0))
        p = float(obj["p_malicious"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None, "unparseable model reply"
    return max(0.0, min(1.0, p)), str(obj.get("rationale", ""))


def run_model(model_id: str, prompts: list[dict], limit: int | None,
              suffix: str = "") -> None:
    from mlx_lm import generate, load

    slug = model_id.replace("/", "_")
    out_path = OUT_DIR / f"responses_{slug}{suffix}.jsonl"
    done: set[str] = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            try:
                done.add(json.loads(line)["key"])
            except (json.JSONDecodeError, KeyError):
                continue

    todo = prompts[:limit] if limit else prompts
    keys = [hashlib.sha256(f"{model_id}\x00{p['prompt']}".encode()).hexdigest()
            for p in todo]
    remaining = sum(1 for k in keys if k not in done)
    print(f"\n=== {model_id}: {remaining}/{len(todo)} to score "
          f"({len(done)} already cached) ===", flush=True)
    if remaining == 0:
        return

    model, tokenizer = load(model_id)
    n_null = 0
    t0 = time.time()
    scored = 0
    with out_path.open("a", encoding="utf-8") as fh:
        for item, key in zip(todo, keys):
            if key in done:
                continue
            chat = tokenizer.apply_chat_template(
                [{"role": "user", "content": item["prompt"]}],
                add_generation_prompt=True,
                tokenize=False,
            )
            text = generate(model, tokenizer, prompt=chat,
                            max_tokens=MAX_TOKENS, verbose=False)
            p, rationale = parse_reply(text)
            if p is None:
                n_null += 1
            fh.write(json.dumps({
                "key": key,
                "model": model_id,
                "p_malicious": p,
                "rationale": rationale,
                "raw_response": text,
            }) + "\n")
            fh.flush()
            scored += 1
            if scored % 25 == 0:
                rate = scored / (time.time() - t0)
                eta_min = (remaining - scored) / rate / 60 if rate else 0
                print(f"  {scored}/{remaining} (nulls={n_null}, "
                      f"{rate:.2f}/s, eta {eta_min:.0f}m)", flush=True)

    del model, tokenizer
    gc.collect()
    try:
        import mlx.core as mx
        mx.clear_cache()
    except Exception:
        pass
    print(f"=== {model_id}: done, {n_null} nulls -> {out_path.name} ===",
          flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--prompts", default=str(PROMPTS_PATH),
                        help="prompt set to score (e.g. prompts_k0.jsonl for the "
                             "judge-context sweep); output files are suffixed with the "
                             "prompt-set name when it is not the default")
    args = parser.parse_args()

    prompts_path = Path(args.prompts)
    suffix = ""
    if prompts_path.resolve() != PROMPTS_PATH.resolve():
        suffix = "_" + prompts_path.stem.replace("prompts_", "")
    prompts = [json.loads(l) for l in
               prompts_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"{len(prompts)} prompts loaded from {prompts_path.name}")
    for model_id in args.models:
        try:
            run_model(model_id, prompts, args.limit, suffix)
        except Exception as exc:  # keep the queue alive past one bad model
            print(f"!!! {model_id} FAILED: {type(exc).__name__}: {exc}", flush=True)


if __name__ == "__main__":
    main()
