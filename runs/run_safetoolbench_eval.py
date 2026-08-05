"""Gate evaluation on VERBATIM SafeToolBench items (Xia et al., EMNLP 2025 Findings).

Provenance
----------
Items are loaded verbatim from the released corpus at
github.com/BITHLP/SafeToolBench (data/data/query_{PD,PL,PI,BO}_{SA,MA}.json;
clone the repo and pass --data-dir). This corpus was NOT reachable at the
original 2026-07-22 tool-use run (only the paper's abstract/figure text was
public then); it has since been released, so this run closes the
"verbatim SafeToolBench items" future-work item at the gate level.

Scope and honest caveats
------------------------
* Every released item is RISKY-labeled (4 risk categories x single/multi-API);
  there is no safe subset. This run therefore measures the gate's
  prospective-risk FLAG RATE (sensitivity) on real benchmark items. The
  false-positive side of the gate is still covered by the repo's authored
  20-safe-scenario suite and the 152-command hard-benign set.
* SafeToolBench's published metrics score LLM risk *awareness* across nine
  dimensions; our metric is a cost-derived EXECUTE/BLOCK decision at p*=0.40.
  Numbers here are NOT comparable to published SafeToolBench scores.
* Each item ships the proposed API call(s) (name + arguments), so no planner
  is involved: we gate exactly the calls the benchmark specifies. An item
  counts as FLAGGED if at least one of its calls is decided STOP.
* Many items are mild (e.g. "delete all my events from last month" -> risk of
  data loss). A low rule-only flag rate on such items is expected: the rule
  scorer only pattern-matches destructive/exfil/credential/privacy/financial
  strings; contextual risk is the LLM judge's job.

Usage
-----
    python runs/run_safetoolbench_eval.py --data-dir /path/to/SafeToolBench/data/data
    # rule-only over all items, plus combined rule+LLM on a seeded stratified
    # sample of --llm-per-file items per category file (default 25 -> 200).
    python runs/run_safetoolbench_eval.py --data-dir ... --no-llm   # rule-only
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tmdp_sandbox.llm_judge import DEFAULT_MODEL, LLMJudge
from tmdp_sandbox.tooluse_agent import PendingAction, SafetyGate

OUT_DIR = Path(__file__).parent / "safetoolbench_eval"
CACHE_PATH = OUT_DIR / "responses.jsonl"

CATEGORY_FILES = [
    "query_PD_SA.json",
    "query_PD_MA.json",
    "query_PL_SA.json",
    "query_PL_MA.json",
    "query_PI_SA.json",
    "query_PI_MA.json",
    "query_BO_SA.json",
    "query_BO_MA.json",
]


def load_items(data_dir: Path) -> list[dict]:
    items: list[dict] = []
    for fname in CATEGORY_FILES:
        fpath = data_dir / fname
        raw = json.loads(fpath.read_text())
        stem = fpath.stem  # query_PD_SA
        _, cat, arity = stem.split("_")
        for idx, rec in enumerate(raw):
            calls = []
            for api_entry in rec.get("output", {}).get("used_api", []):
                for api_name, api_args in api_entry.items():
                    if api_name == "use_times":
                        continue
                    if not isinstance(api_args, dict):
                        api_args = {"value": api_args}
                    calls.append((api_name, api_args))
            if not calls:
                continue
            items.append(
                {
                    "uid": f"{stem}-{idx:03d}",
                    "file": fname,
                    "category": cat,
                    "arity": arity,
                    "instruction": rec.get("instruction", ""),
                    "risk_category": rec.get("Risk category", ""),
                    "apps": rec.get("output", {}).get("used_app", []),
                    "quality_score": rec.get("quality_score"),
                    "calls": calls,
                }
            )
    return items


def gate_item(gate: SafetyGate, item: dict, *, use_llm: bool) -> dict:
    context = {
        "user_request": item["instruction"],
        "apps_in_use": ", ".join(item["apps"]),
        "note": "single pending assistant action(s) proposed for this request",
    }
    decisions = []
    for tool_name, tool_args in item["calls"]:
        d = gate.evaluate(
            PendingAction(tool_name=tool_name, tool_args=tool_args),
            context,
            use_llm=use_llm,
        )
        decisions.append(
            {
                "tool_name": d.tool_name,
                "rule_score": d.rule_score,
                "rule_categories": list(d.rule_categories),
                "llm_score": d.llm_score,
                "combined_score": d.combined_score,
                "decision": d.decision,
                "cached_llm": d.cached_llm,
            }
        )
    flagged = any(d["decision"] == "STOP" for d in decisions)
    max_combined = max(d["combined_score"] for d in decisions)
    return {
        "uid": item["uid"],
        "category": item["category"],
        "arity": item["arity"],
        "flagged": flagged,
        "max_combined": max_combined,
        "n_calls": len(decisions),
        "decisions": decisions,
    }


def rate_rows(rows: list[dict]) -> dict:
    by_key: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_key["overall"].append(r)
        by_key[f"cat_{r['category']}"].append(r)
        by_key[f"arity_{r['arity']}"].append(r)
    out = {}
    for key, group in sorted(by_key.items()):
        n = len(group)
        f = sum(1 for g in group if g["flagged"])
        out[key] = {"n": n, "flagged": f, "rate": round(f / n, 4) if n else None}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--llm-per-file", type=int, default=25)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    items = load_items(args.data_dir)
    print(f"Loaded {len(items)} risky-labeled items from {args.data_dir}")

    try:
        commit = subprocess.run(
            ["git", "-C", str(args.data_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except Exception:
        commit = "unknown"

    # ── rule-only pass over ALL items (no CLI calls) ────────────────────────
    rule_gate = SafetyGate(judge=None, allow_defer=False)
    rule_rows = [gate_item(rule_gate, it, use_llm=False) for it in items]
    rule_rates = rate_rows(rule_rows)
    print("rule-only flag rate (all items):", rule_rates["overall"])

    # ── combined rule+LLM pass on a seeded stratified sample ───────────────
    combined_rows: list[dict] = []
    sample_uids: list[str] = []
    if not args.no_llm:
        rng = random.Random(args.seed)
        sample: list[dict] = []
        by_file: dict[str, list[dict]] = defaultdict(list)
        for it in items:
            by_file[it["file"]].append(it)
        for fname in CATEGORY_FILES:
            pool = by_file[fname]
            k = min(args.llm_per_file, len(pool))
            sample.extend(rng.sample(pool, k))
        sample_uids = [it["uid"] for it in sample]
        judge = LLMJudge(model=args.model, cache_path=CACHE_PATH)
        llm_gate = SafetyGate(judge=judge, allow_defer=False)

        def _run(it: dict) -> dict:
            return gate_item(llm_gate, it, use_llm=True)

        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool_ex:
            combined_rows = list(pool_ex.map(_run, sample))
        combined_rates = rate_rows(combined_rows)
        n_null = sum(
            1
            for r in combined_rows
            for d in r["decisions"]
            if d["llm_score"] is None
        )
        print("combined flag rate (sample):", combined_rates["overall"], f"llm_null_calls={n_null}")
    else:
        combined_rates = {}
        n_null = 0

    results = {
        "provenance": {
            "source": "github.com/BITHLP/SafeToolBench data/data (verbatim items)",
            "dataset_commit": commit,
            "all_items_risky_labeled": True,
            "metric": "item flagged = any proposed call decided STOP at cost-derived p*=0.40",
            "not_comparable_to_published_scores": True,
            "seed": args.seed,
            "llm_per_file": None if args.no_llm else args.llm_per_file,
            "model": None if args.no_llm else args.model,
        },
        "n_items": len(items),
        "rule_only": {"rates": rule_rates},
        "combined": {
            "rates": combined_rates,
            "sample_uids": sample_uids,
            "llm_null_calls": n_null,
        },
        "rows_rule_only": rule_rows,
        "rows_combined": combined_rows,
    }
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=1))

    lines = [
        "SafeToolBench VERBATIM-ITEM gate evaluation (prospective-risk flag rate)",
        "=" * 74,
        f"Dataset: BITHLP/SafeToolBench @ {commit[:12]}  |  {len(items)} items, ALL risky-labeled",
        "Metric: item flagged if any proposed API call is STOPped at p*=0.40.",
        "NOT comparable to published SafeToolBench scores (different metric).",
        "",
        "Rule-only (all items):",
    ]
    for key, v in rule_rates.items():
        lines.append(f"  {key:12s} {v['flagged']:4d}/{v['n']:<4d} = {v['rate']:.1%}")
    if combined_rates:
        lines += ["", f"Combined 0.4*rule + 0.6*LLM ({args.model}; stratified sample):"]
        for key, v in combined_rates.items():
            lines.append(f"  {key:12s} {v['flagged']:4d}/{v['n']:<4d} = {v['rate']:.1%}")
        lines.append(f"  (LLM null responses among sampled calls: {n_null})")
    summary = "\n".join(lines) + "\n"
    (OUT_DIR / "summary.txt").write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
