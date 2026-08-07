# Judge model comparison (experimental sweep)

Same frozen 542-event plan (seed 42) for every row; sorted by ECE.
`k` is the judge-prompt context window (classifier features always k=10).

| Judge model | k | ECE | Brier | Hard-benign FP @0.40 | Nulls |
|---|---|---|---|---|---|
| mlx-community/Qwen2.5-14B-Instruct-4bit | 10 | 0.0303 | 0.1384 | 1/146 (0.7%) | 10 |
| mlx-community/Qwen2.5-7B-Instruct-4bit | 0 | 0.0348 | 0.1741 | 45/152 (29.6%) | 0 |
| claude-opus-5 | 10 | 0.0541 | 0.1040 | 2/152 (1.3%) | 0 |
| claude-opus-4-8 | 10 | 0.0663 | 0.1101 | 8/151 (5.3%) | 3 |
| mlx-community/Mistral-7B-Instruct-v0.3-4bit | 10 | 0.1225 | 0.1774 | 9/109 (8.3%) | 89 |
| mlx-community/Qwen2.5-7B-Instruct-8bit | 10 | 0.1253 | 0.1769 | 21/151 (13.9%) | 2 |
| mlx-community/Qwen2.5-7B-Instruct-4bit | 3 | 0.1278 | 0.1878 | 61/151 (40.4%) | 1 |
| mlx-community/Qwen2.5-7B-Instruct-4bit | 10 | 0.1438 | 0.1839 | 55/151 (36.4%) | 1 |
| mlx-community/Qwen2.5-3B-Instruct-4bit | 10 | 0.1797 | 0.2192 | 0/145 (0.0%) | 17 |
| mlx-community/Meta-Llama-3.1-8B-Instruct-4bit | 10 | 0.2995 | 0.2640 | 91/119 (76.5%) | 49 |
| mlx-community/Phi-3.5-mini-instruct-4bit | 10 | 0.3448 | 0.3076 | 75/125 (60.0%) | 81 |
| mlx-community/Qwen2.5-1.5B-Instruct-4bit | 10 | 0.5422 | 0.5470 | 72/110 (65.5%) | 100 |
| mlx-community/Qwen2.5-0.5B-Instruct-4bit | 10 | 0.6446 | 0.6277 | 124/124 (100.0%) | 113 |
| *(classifier, all runs)* | 10 | 0.3456 | 0.2883 | 152/152 (100.0%) | — |
