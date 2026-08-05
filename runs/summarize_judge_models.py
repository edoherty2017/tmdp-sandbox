"""Comparison table for all judge-model calibration runs.

Walks every runs/llm_judge_calibration*/results.json and prints one markdown
row per run: model, judge context window, overall ECE / Brier, hard-benign
FP at the deployed p*=0.40, and null count. The classifier row (identical in
every run) is printed once from the baseline artifacts for reference.

Usage:
    python runs/summarize_judge_models.py [--write docs/experiments/judge-model-comparison.md]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).parent


def load_row(results_path: Path) -> dict | None:
    try:
        r = json.loads(results_path.read_text(encoding="utf-8"))
        ov = r["metrics"]["overall"]
        cal = ov["llm_judge"]["calibration"]
        fp40 = next(x for x in r["hard_benign_fp"]["llm_judge"]
                    if abs(x["threshold"] - 0.40) < 1e-9)
        return {
            "run": results_path.parent.name,
            "model": r["metadata"]["model"],
            "judge_window": r["metadata"].get("judge_window",
                                              r["metadata"].get("window_size", "?")),
            "n": ov["n"],
            "nulls": ov["llm_null_count"],
            "ece": cal["ece"],
            "brier": cal["brier"],
            "fp": f"{fp40['fp']}/{fp40['n']}",
            "fp_rate": fp40["fp_rate"],
        }
    except (KeyError, StopIteration, json.JSONDecodeError) as exc:
        print(f"  (skipping {results_path.parent.name}: {exc!r})")
        return None


def classifier_row(results_path: Path) -> dict | None:
    try:
        r = json.loads(results_path.read_text(encoding="utf-8"))
        cal = r["metrics"]["overall"]["classifier"]["calibration"]
        fp40 = next(x for x in r["hard_benign_fp"]["classifier"]
                    if abs(x["threshold"] - 0.40) < 1e-9)
        return {"ece": cal["ece"], "brier": cal["brier"],
                "fp": f"{fp40['fp']}/{fp40['n']}", "fp_rate": fp40["fp_rate"]}
    except (KeyError, StopIteration, json.JSONDecodeError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", default=None,
                        help="also write the markdown table to this path")
    args = parser.parse_args()

    rows = []
    for d in sorted(HERE.glob("llm_judge_calibration*")):
        rp = d / "results.json"
        if rp.exists():
            row = load_row(rp)
            if row and row["n"] >= 500:  # skip smoke runs
                rows.append(row)
    rows.sort(key=lambda r: r["ece"])

    lines = [
        "| Judge model | k | ECE | Brier | Hard-benign FP @0.40 | Nulls |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['model']} | {r['judge_window']} | {r['ece']:.4f} | "
            f"{r['brier']:.4f} | {r['fp']} ({r['fp_rate']:.1%}) | {r['nulls']} |")
    base = HERE / "llm_judge_calibration" / "results.json"
    c = classifier_row(base) if base.exists() else None
    if c:
        lines.append(
            f"| *(classifier, all runs)* | 10 | {c['ece']:.4f} | {c['brier']:.4f} | "
            f"{c['fp']} ({c['fp_rate']:.1%}) | — |")

    table = "\n".join(lines)
    print(table)
    if args.write:
        out = Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            "# Judge model comparison (experimental sweep)\n\n"
            "Same frozen 542-event plan (seed 42) for every row; sorted by ECE.\n"
            "`k` is the judge-prompt context window (classifier features always k=10).\n\n"
            + table + "\n",
            encoding="utf-8")
        print(f"\nwritten -> {out}")


if __name__ == "__main__":
    main()
