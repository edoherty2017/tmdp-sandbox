#!/bin/bash
# Re-run the two disk-space victims sequentially, freeing the ~8GB model
# cache between them (both cannot fit in the remaining disk at once).
# Resumable like everything else.
set -u
PY=/Users/ethandoherty/tmdp-sandbox/.venv/bin/python
cd "$(dirname "$0")/.."
R=runs/run_oss_judges_local.py
OSS=runs/oss_judges
HUB=/Users/ethandoherty/.cache/huggingface/hub

echo "=== Straggler 1: Qwen2.5-14B-4bit ==="
$PY $R --models mlx-community/Qwen2.5-14B-Instruct-4bit
$PY runs/run_llm_judge_calibration.py --model mlx-community/Qwen2.5-14B-Instruct-4bit \
  --external-responses $OSS/responses_mlx-community_Qwen2.5-14B-Instruct-4bit.jsonl \
  --out-dir runs/llm_judge_calibration_qwen25-14b-4bit --judge-window 10 || true
rm -rf "$HUB/models--mlx-community--Qwen2.5-14B-Instruct-4bit"
echo "=== 14B cache freed ==="

echo "=== Straggler 2: Qwen2.5-7B-8bit ==="
$PY $R --models mlx-community/Qwen2.5-7B-Instruct-8bit
$PY runs/run_llm_judge_calibration.py --model mlx-community/Qwen2.5-7B-Instruct-8bit \
  --external-responses $OSS/responses_mlx-community_Qwen2.5-7B-Instruct-8bit.jsonl \
  --out-dir runs/llm_judge_calibration_qwen25-7b-8bit --judge-window 10 || true

echo "=== Regenerating comparison table ==="
$PY runs/summarize_judge_models.py --write docs/experiments/judge-model-comparison.md
echo "=== Stragglers complete ==="
