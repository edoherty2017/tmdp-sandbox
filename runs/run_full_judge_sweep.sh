#!/bin/bash
# Full open-source judge sweep: families, sizes, quantization, context windows.
#
# FULLY RESUMABLE: every stage skips work that is already done, so this script
# is safe to interrupt (sleep, shutdown, ctrl-C) and re-run any number of
# times — it always continues where it left off.
#
# Run it with the Mac plugged in and prevented from sleeping:
#     caffeinate -is bash runs/run_full_judge_sweep.sh
#
# Rough wall-clock on an M1 Pro (measured 0.17 prompts/s for 7B-4bit):
#   stage 1 family sweep  (4 models)  ~3.5 h
#   stage 2 size ladder   (4 models)  ~3.5 h   (0.5B/1.5B/3B fast; 14B ~2 h)
#   stage 3 quantization  (7B-8bit)   ~1.5 h
#   stage 4 context k0/k3 (7B-4bit)   ~1.5 h
#   stage 5 scoring + table           ~10 min (offline replay)
#   total                             ~10 h unattended (+ ~25 GB model downloads)

set -u
PY=/Users/ethandoherty/tmdp-sandbox/.venv/bin/python
cd "$(dirname "$0")/.."
R=runs/run_oss_judges_local.py
OSS=runs/oss_judges

echo "=== Stage 1: family sweep (7-8B class, 4-bit) ==="
$PY $R --models \
  mlx-community/Qwen2.5-7B-Instruct-4bit \
  mlx-community/Phi-3.5-mini-instruct-4bit \
  mlx-community/Meta-Llama-3.1-8B-Instruct-4bit \
  mlx-community/Mistral-7B-Instruct-v0.3-4bit

echo "=== Stage 2: size ladder (Qwen2.5 family, 4-bit) ==="
$PY $R --models \
  mlx-community/Qwen2.5-0.5B-Instruct-4bit \
  mlx-community/Qwen2.5-1.5B-Instruct-4bit \
  mlx-community/Qwen2.5-3B-Instruct-4bit \
  mlx-community/Qwen2.5-14B-Instruct-4bit

echo "=== Stage 3: quantization (same 7B weights, 8-bit) ==="
$PY $R --models mlx-community/Qwen2.5-7B-Instruct-8bit

echo "=== Stage 4: judge context window (7B-4bit on k=0 and k=3 prompts) ==="
$PY $R --prompts $OSS/prompts_k0.jsonl --models mlx-community/Qwen2.5-7B-Instruct-4bit
$PY $R --prompts $OSS/prompts_k3.jsonl --models mlx-community/Qwen2.5-7B-Instruct-4bit

echo "=== Stage 5: score everything through the frozen pipeline ==="
score () { # model responses out-dir judge-window
  if [ -s "$2" ]; then
    $PY runs/run_llm_judge_calibration.py --model "$1" \
      --external-responses "$2" --out-dir "$3" --judge-window "$4" || true
  else
    echo "skip (no responses yet): $2"
  fi
}
score mlx-community/Qwen2.5-7B-Instruct-4bit        $OSS/responses_mlx-community_Qwen2.5-7B-Instruct-4bit.jsonl        runs/llm_judge_calibration_qwen25-7b-4bit      10
score mlx-community/Phi-3.5-mini-instruct-4bit      $OSS/responses_mlx-community_Phi-3.5-mini-instruct-4bit.jsonl      runs/llm_judge_calibration_phi35-mini-4bit     10
score mlx-community/Meta-Llama-3.1-8B-Instruct-4bit $OSS/responses_mlx-community_Meta-Llama-3.1-8B-Instruct-4bit.jsonl runs/llm_judge_calibration_llama31-8b-4bit     10
score mlx-community/Mistral-7B-Instruct-v0.3-4bit   $OSS/responses_mlx-community_Mistral-7B-Instruct-v0.3-4bit.jsonl   runs/llm_judge_calibration_mistral7b-4bit      10
score mlx-community/Qwen2.5-0.5B-Instruct-4bit      $OSS/responses_mlx-community_Qwen2.5-0.5B-Instruct-4bit.jsonl      runs/llm_judge_calibration_qwen25-05b-4bit     10
score mlx-community/Qwen2.5-1.5B-Instruct-4bit      $OSS/responses_mlx-community_Qwen2.5-1.5B-Instruct-4bit.jsonl      runs/llm_judge_calibration_qwen25-15b-4bit     10
score mlx-community/Qwen2.5-3B-Instruct-4bit        $OSS/responses_mlx-community_Qwen2.5-3B-Instruct-4bit.jsonl        runs/llm_judge_calibration_qwen25-3b-4bit      10
score mlx-community/Qwen2.5-14B-Instruct-4bit       $OSS/responses_mlx-community_Qwen2.5-14B-Instruct-4bit.jsonl       runs/llm_judge_calibration_qwen25-14b-4bit     10
score mlx-community/Qwen2.5-7B-Instruct-8bit        $OSS/responses_mlx-community_Qwen2.5-7B-Instruct-8bit.jsonl        runs/llm_judge_calibration_qwen25-7b-8bit      10
score mlx-community/Qwen2.5-7B-Instruct-4bit        $OSS/responses_mlx-community_Qwen2.5-7B-Instruct-4bit_k0.jsonl     runs/llm_judge_calibration_qwen25-7b-4bit-k0    0
score mlx-community/Qwen2.5-7B-Instruct-4bit        $OSS/responses_mlx-community_Qwen2.5-7B-Instruct-4bit_k3.jsonl     runs/llm_judge_calibration_qwen25-7b-4bit-k3    3

echo "=== Comparison table ==="
$PY runs/summarize_judge_models.py --write docs/experiments/judge-model-comparison.md
echo "=== Sweep complete ==="
