"""Generate publication-quality figures for the CS5100 T-MDP Security report.

Outputs five high-DPI PNG figures to docs/figures/.

Usage:
    python runs/generate_figures.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless rendering
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
import numpy as np
from matplotlib.gridspec import GridSpec
from matplotlib.lines import Line2D
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO = Path(__file__).parent.parent
FIGURES = REPO / "docs" / "figures"
FIGURES.mkdir(parents=True, exist_ok=True)

NOISE_AGGREGATE = REPO / "runs" / "security_batch" / "aggregate.json"
COST_AGGREGATE  = REPO / "runs" / "security_cost_sweep" / "aggregate.json"
CAL_RESULTS     = REPO / "runs" / "calibration_eval" / "results.json"
SEQ_AGGREGATE   = REPO / "runs" / "sequential_eval" / "aggregate.json"

# ---------------------------------------------------------------------------
# Shared style
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "legend.fontsize": 9,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linewidth": 0.5,
})

# Color palette (colorblind-friendly)
C_TMDP      = "#2166AC"   # blue
C_TMDP2     = "#6BAED6"   # light blue (nodefer / stop-on-first)
C_THRESH05  = "#E6550D"   # orange
C_THRESH03  = "#31A354"   # green
C_THRESH07  = "#D94801"   # dark red-orange
C_ORACLE    = "#756BB1"   # purple
C_SEQ       = "#238B45"   # dark green (sequential)
C_DANGER    = "#CB181D"   # red (malicious zone)
C_NEUTRAL   = "#636363"   # gray


# ===========================================================================
# Figure 1 — Three-Phase Pipeline Architecture
# ===========================================================================
def fig_pipeline_architecture() -> None:
    fig, ax = plt.subplots(figsize=(12, 4.2))
    ax.set_xlim(0, 12.2)
    ax.set_ylim(0, 4.2)
    ax.axis("off")
    ax.set_facecolor("#FAFAFA")
    fig.patch.set_facecolor("#FAFAFA")

    # ---- helper to draw a phase box ----------------------------------------
    def draw_phase(x, label, color, bg, lines, stats):
        """x is centre-x; box spans x±1.4."""
        bx = x - 1.45
        bw = 2.90
        # shadow
        shadow = FancyBboxPatch((bx + 0.04, 0.22), bw, 3.2,
                                boxstyle="round,pad=0.08",
                                facecolor="#CCCCCC", edgecolor="none", zorder=1)
        ax.add_patch(shadow)
        # box
        box = FancyBboxPatch((bx, 0.26), bw, 3.2,
                             boxstyle="round,pad=0.08",
                             facecolor=bg, edgecolor=color,
                             linewidth=2, zorder=2)
        ax.add_patch(box)
        # phase label (top band)
        band = FancyBboxPatch((bx, 3.10), bw, 0.36,
                              boxstyle="round,pad=0.05",
                              facecolor=color, edgecolor="none", zorder=3)
        ax.add_patch(band)
        ax.text(x, 3.28, label, ha="center", va="center",
                fontsize=9.5, fontweight="bold", color="white", zorder=4)
        # content lines
        for i, ln in enumerate(lines):
            ax.text(x, 2.85 - i * 0.44, ln, ha="center", va="center",
                    fontsize=8.2, color="#111111", zorder=4)
        # stat bubbles
        for j, (key, val) in enumerate(stats):
            bby = 0.56 + j * 0.34
            bubble = FancyBboxPatch((bx + 0.15, bby - 0.13), bw - 0.30, 0.28,
                                   boxstyle="round,pad=0.04",
                                   facecolor="#FFFFFF", edgecolor=color,
                                   linewidth=1, alpha=0.85, zorder=4)
            ax.add_patch(bubble)
            ax.text(x, bby + 0.01, f"{key}  {val}", ha="center", va="center",
                    fontsize=7.5, color=color, fontweight="bold", zorder=5)

    # ---- helper for arrows -------------------------------------------------
    def arrow(x1, x2, y=1.95, label=""):
        ax.annotate("", xy=(x2, y), xytext=(x1, y),
                    arrowprops=dict(arrowstyle="-|>", color="#444444",
                                   lw=1.6, mutation_scale=14),
                    zorder=6)
        if label:
            ax.text((x1 + x2) / 2, y + 0.18, label,
                    ha="center", va="bottom", fontsize=7.5, color="#444444")

    # ---- Phase boxes -------------------------------------------------------
    draw_phase(
        1.9, "PHASE 1 — Baseline Integrity",
        "#1B4F72", "#EBF5FB",
        ["Baseline process allow-list", "LOLBin / UAC-bypass list (42)", "Obfuscation pattern scan",
         "Sliding-window context features"],
        [("Techniques", "EID + proc + cmdline"), ("Window", "10 events")],
    )

    draw_phase(
        5.5, "PHASE 2 — ML Classifier",
        "#1A5276", "#EBF5FB",
        ["TF-IDF on cmdline / process",
         "12 numeric handcrafted features",
         "CalibratedClassifierCV",
         "Outputs P(malicious) ∈ [0,1]"],
        [("CV F1", "1.000 ± 0.000"), ("ECE", "0.0000  (fully binary)")],
    )

    draw_phase(
        9.1, "PHASE 3 — T-MDP Decision",
        "#154360", "#EBF5FB",
        ["Value iteration over P(malicious)",
         "Closed-form threshold: p* = Δc / c_comp",
         "EXECUTE / BLOCK_EVENT / DEFER",
         "No manual threshold tuning"],
        [("p* = 4/c_comp", "e.g. 0.40 @ c=10"), ("Safety", "mal_block = 1.000")],
    )

    # ---- Arrows -----------------------------------------------------------
    arrow(3.40, 4.05, y=1.95, label="integrity + context")
    arrow(7.00, 7.65, y=1.95, label="P(malicious)")

    # ---- INPUT / OUTPUT labels -------------------------------------------
    # Raw event stream input arrow
    ax.annotate("", xy=(0.45, 1.95), xytext=(0.02, 1.95),
                arrowprops=dict(arrowstyle="-|>", color="#888888",
                                lw=1.4, mutation_scale=12), zorder=6)
    ax.text(0.02, 2.22, "Windows\nSysmon\nevents", ha="center", va="bottom",
            fontsize=7.5, color="#555555")

    # Output actions
    for i, (action, col, y_off) in enumerate([
        ("EXECUTE",     C_THRESH03,  2.45),
        ("BLOCK_EVENT", C_TMDP,      1.95),
        ("DEFER",       C_THRESH05,  1.45),
    ]):
        ax.annotate("", xy=(11.15, y_off), xytext=(10.85, y_off),
                    arrowprops=dict(arrowstyle="-|>", color=col,
                                   lw=1.4, mutation_scale=11), zorder=6)
        ax.text(11.20, y_off, action, va="center", fontsize=8, color=col,
                fontweight="bold")

    # ---- Title / caption --------------------------------------------------
    ax.text(5.5, 4.05, "T-MDP Security Classification Pipeline",
            ha="center", va="center", fontsize=13, fontweight="bold",
            color="#1A1A1A")

    fig.tight_layout()
    out = FIGURES / "fig1_pipeline_architecture.png"
    fig.savefig(out, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Saved {out}")


# ===========================================================================
# Figure 2 — Noise Sweep: T-MDP vs Fixed Thresholds
# ===========================================================================
def fig_noise_sweep() -> None:
    data = json.loads(NOISE_AGGREGATE.read_text())
    sigmas = sorted(float(s) for s in data)

    def series(policy_key: str, metric: str) -> list[float]:
        out = []
        for s in sigmas:
            bucket = data[str(s)]
            # find matching key (may have sigma suffix or not)
            for k, v in bucket.items():
                if k == policy_key:
                    out.append(v[metric])
                    break
            else:
                out.append(float("nan"))
        return out

    mal_tmdp   = series("tmdp-p0.40",   "malicious_executed_rate")
    mal_t05    = series("threshold-0.5", "malicious_executed_rate")
    mal_t07    = series("threshold-0.7", "malicious_executed_rate")
    mal_t03    = series("threshold-0.3", "malicious_executed_rate")
    ben_tmdp   = series("tmdp-p0.40",   "mean_benign_allow_rate")
    ben_t05    = series("threshold-0.5", "mean_benign_allow_rate")

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.0), sharey=False)
    ax1, ax2 = axes

    # ---- Left: malicious execution rate ------------------------------------
    sx = sigmas
    ax1.plot(sx, mal_t07, "D--", color=C_THRESH07, lw=1.6, ms=5, label="Threshold 0.7")
    ax1.plot(sx, mal_t05, "s--", color=C_THRESH05, lw=1.6, ms=5, label="Threshold 0.5")
    ax1.plot(sx, mal_tmdp,"o-",  color=C_TMDP,    lw=2.2, ms=6, label="T-MDP (p*=0.40)", zorder=5)
    ax1.plot(sx, mal_t03, "^:",  color=C_THRESH03, lw=1.5, ms=5, label="Threshold 0.3")
    ax1.plot(sx, [0]*len(sx), "k--", lw=1.2, alpha=0.5, label="Oracle (0%)")

    # shade the divergence zone between T-MDP and threshold-0.5
    ax1.fill_between(sx, mal_tmdp, mal_t05, alpha=0.12, color=C_TMDP,
                     label="T-MDP advantage")

    ax1.set_xlabel("Risk score noise σ")
    ax1.set_ylabel("Malicious execution rate")
    ax1.set_title("(a)  Malicious Execution Rate vs. Noise", pad=8)
    ax1.set_xticks(sx)
    ax1.set_xticklabels([f"{s:.2f}" for s in sx])
    ax1.set_ylim(-0.003, 0.09)
    ax1.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.1%}")
    )
    ax1.legend(loc="upper left", framealpha=0.9)

    # annotation: T-MDP is never worse
    ax1.text(0.10, 0.014,
             "T-MDP ≤ threshold-0.5\nat all noise levels",
             ha="left", va="bottom", fontsize=8,
             color=C_TMDP, style="italic",
             bbox=dict(facecolor="white", alpha=0.7, edgecolor="none", pad=2))

    # ---- Right: benign allow rate degradation under noise ------------------
    ax2.plot(sx, ben_t05,  "s--", color=C_THRESH05, lw=1.6, ms=5, label="Threshold 0.5")
    ax2.plot(sx, ben_tmdp, "o-",  color=C_TMDP,    lw=2.2, ms=6, label="T-MDP (p*=0.40)", zorder=5)

    ax2.set_xlabel("Risk score noise σ")
    ax2.set_ylabel("Benign-allow rate (stop-on-first mode)")
    ax2.set_title("(b)  Benign Allow Rate vs. Noise", pad=8)
    ax2.set_xticks(sx)
    ax2.set_xticklabels([f"{s:.2f}" for s in sx])
    ax2.set_ylim(0.26, 0.38)
    ax2.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.1%}")
    )
    ax2.legend(loc="upper right", framealpha=0.9)

    # annotation: high noise harms benign-allow — placed as a footer text box
    ax2.text(0.50, 0.04,
             "Benign-allow drops under high noise (stop-on-first artefact)\n"
             "→ resolved by sequential block architecture (Fig. 5)",
             transform=ax2.transAxes, ha="center", va="bottom",
             fontsize=7.5, color="#555555", style="italic",
             bbox=dict(facecolor="white", alpha=0.85, edgecolor="#BBBBBB",
                       pad=3, boxstyle="round,pad=0.3"))

    fig.suptitle("Noise Robustness — T-MDP vs. Fixed-Threshold Policies\n"
                 "(n=500 scenarios, malicious fraction=0.2)",
                 fontsize=12, fontweight="bold", y=1.02)
    fig.tight_layout()
    out = FIGURES / "fig2_noise_sweep.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out}")


# ===========================================================================
# Figure 3 — Cost Sweep: T-MDP Threshold Adaptivity
# ===========================================================================
def fig_cost_sweep() -> None:
    data = json.loads(COST_AGGREGATE.read_text())
    c_vals   = sorted(float(c) for c in data)  # [10, 50, 100, 500]
    p_stars  = [4.0 / c for c in c_vals]       # derived threshold

    def get_metric(c: float, policy_substr: str, key: str) -> float:
        bucket = data[str(c)]
        for name, v in bucket.items():
            if policy_substr in name:
                return v[key]
        return float("nan")

    ben_tmdp    = [get_metric(c, "tmdp-p*=",        "mean_benign_allow_rate") for c in c_vals]
    ben_nodefer = [get_metric(c, "tmdp-nodefer-p*=", "mean_benign_allow_rate") for c in c_vals]
    ben_t05     = [get_metric(c, "threshold-0.5",    "mean_benign_allow_rate") for c in c_vals]
    mal_tmdp    = [get_metric(c, "tmdp-p*=",         "malicious_executed_rate") for c in c_vals]
    mal_t05     = [get_metric(c, "threshold-0.5",    "malicious_executed_rate") for c in c_vals]

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    ax1, ax2 = axes

    # ---- Left: threshold derivation p* vs c_compromise --------------------
    c_smooth = np.logspace(np.log10(8), np.log10(600), 200)
    p_smooth = 4.0 / c_smooth

    ax1.plot(c_smooth, p_smooth, "-", color=C_TMDP, lw=2.0, label=r"$p^* = \Delta c\,/\,c_\mathrm{comp}$")
    ax1.scatter(c_vals, p_stars, color=C_TMDP, s=70, zorder=5,
                label="Evaluated operating points")

    # label each point
    offsets = {10: (-0.5, 0.03), 50: (4, 0.005), 100: (5, 0.003), 500: (10, 0.0005)}
    for c, p in zip(c_vals, p_stars):
        dx, dy = offsets.get(c, (5, 0))
        ax1.annotate(f"c={int(c):,}\np*={p:.3f}",
                     xy=(c, p), xytext=(c + dx, p + dy),
                     fontsize=7.5, color=C_TMDP,
                     arrowprops=dict(arrowstyle="->", color=C_TMDP, lw=0.7))

    # horizontal line at threshold-0.5
    ax1.axhline(0.5, color=C_THRESH05, lw=1.4, ls="--", alpha=0.8, label="Fixed threshold-0.5")
    ax1.text(520, 0.505, "Fixed\nthreshold-0.5", va="bottom", ha="right",
             fontsize=7.5, color=C_THRESH05)

    ax1.set_xscale("log")
    ax1.set_xlabel("Cost of compromise  $c_\\mathrm{comp}$  (log scale)")
    ax1.set_ylabel("Block threshold  $p^*$")
    ax1.set_title("(a)  Threshold Derivation from Cost Ratio", pad=8)
    ax1.legend(loc="upper right", framealpha=0.9)
    ax1.set_ylim(-0.02, 0.58)

    # formula box
    ax1.text(12, 0.33,
             r"$p^* = \frac{c_\mathrm{block}-c_\mathrm{exec}}{c_\mathrm{comp}}$"
             "\n= 4 / $c_\\mathrm{comp}$",
             fontsize=10, color=C_TMDP, va="center",
             bbox=dict(facecolor="#EBF5FB", edgecolor=C_TMDP, pad=5, alpha=0.9))

    # ---- Right: benign-allow rate comparison ------------------------------
    x = np.arange(len(c_vals))
    w = 0.26

    bars1 = ax2.bar(x - w,     ben_t05,     w, color=C_THRESH05, alpha=0.85, label="Threshold-0.5")
    bars2 = ax2.bar(x,         ben_nodefer, w, color=C_TMDP2,    alpha=0.85, label="T-MDP (no DEFER)")
    bars3 = ax2.bar(x + w,     ben_tmdp,    w, color=C_TMDP,     alpha=0.85, label="T-MDP (with DEFER)")

    # Annotate DEFER benefit at c=50
    ax2.annotate("+79%\nvia DEFER",
                 xy=(1 + w, ben_tmdp[1]),
                 xytext=(1 + w + 0.5, ben_tmdp[1] + 0.04),
                 fontsize=7.5, color=C_TMDP, fontweight="bold",
                 arrowprops=dict(arrowstyle="->", color=C_TMDP, lw=0.8),
                 bbox=dict(facecolor="white", alpha=0.7, edgecolor="none"))

    ax2.set_xticks(x)
    ax2.set_xticklabels([f"c={int(c):,}" for c in c_vals])
    ax2.set_xlabel("Cost of compromise  $c_\\mathrm{comp}$")
    ax2.set_ylabel("Benign-allow rate")
    ax2.set_title("(b)  Benign Allow Rate vs. Compromise Cost", pad=8)
    ax2.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0%}")
    )
    ax2.set_ylim(0, 0.44)
    ax2.legend(loc="upper right", framealpha=0.9)

    # note: all T-MDP mal_exec = 0.000 at c≥50
    ax2.text(0.5, 0.01,
             "T-MDP: malicious_exec_rate = 0.000 at c ≥ 50\n"
             "Threshold-0.5: malicious_exec_rate = 1.0% at all costs",
             transform=ax2.transAxes, ha="center", va="bottom",
             fontsize=7.5, color="#444444",
             bbox=dict(facecolor="#FFF8F0", edgecolor=C_THRESH05, alpha=0.9, pad=4))

    fig.suptitle("Cost-Sensitivity Sweep — T-MDP Threshold Adapts to Declared Costs\n"
                 "(n=500 scenarios, σ=0.15, c_block=5, c_exec=1)",
                 fontsize=12, fontweight="bold", y=1.02)
    fig.tight_layout()
    out = FIGURES / "fig3_cost_sweep.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out}")


# ===========================================================================
# Figure 4 — Calibration Reliability Diagram
# ===========================================================================
def fig_calibration() -> None:
    results = json.loads(CAL_RESULTS.read_text())
    indist   = results["in_distribution"]["table"]
    crosstec = results["cross_technique"]["table"]

    def extract_bins(table):
        pts = [((row["bin_low"] + row["bin_high"]) / 2,
                row["mean_predicted"],
                row["actual_rate"],
                row["n"])
               for row in table
               if row["n"] and row["n"] > 0]
        return pts

    in_pts = extract_bins(indist)
    cx_pts = extract_bins(crosstec)

    # Score distribution from table
    in_ns     = [row["n"] for row in indist]
    in_labels = [f"{row['bin_low']:.1f}–{row['bin_high']:.1f}" for row in indist]

    fig = plt.figure(figsize=(10, 4.8))
    gs  = GridSpec(1, 2, figure=fig, wspace=0.35)
    ax1 = fig.add_subplot(gs[0])
    ax2 = fig.add_subplot(gs[1])

    # ---- Left: reliability diagram -----------------------------------------
    # diagonal
    ax1.plot([0, 1], [0, 1], "k--", lw=1.2, alpha=0.5, label="Perfect calibration")

    # shade over-/under-confidence regions
    ax1.fill_between([0, 1], [0, 1], [0, 0], alpha=0.04, color="green",
                     label="Under-confident region")
    ax1.fill_between([0, 1], [1, 1], [0, 1], alpha=0.04, color="red",
                     label="Over-confident region")

    # "desert" shading (0.1 to 0.9 — the no-data zone)
    ax1.axvspan(0.1, 0.9, alpha=0.07, color=C_NEUTRAL, label="No-data desert (0.1–0.9)")

    # in-distribution points (bubble size ∝ sqrt(n))
    for (cx, pred, actual, n) in in_pts:
        size = max(30, math.sqrt(n) * 4.5)
        color = C_TMDP if n > 100 else C_THRESH05
        ax1.scatter([pred], [actual], s=size, color=color,
                    alpha=0.85, zorder=5, edgecolors="white", linewidth=0.8)
        if n > 10:
            ax1.annotate(f"n={n:,}", (pred, actual),
                         textcoords="offset points",
                         xytext=(8, 4), fontsize=7, color=color)

    # cross-technique points
    for (cx, pred, actual, n) in cx_pts:
        size = max(30, math.sqrt(n) * 3)
        ax1.scatter([pred], [actual], s=size, marker="D", color=C_ORACLE,
                    alpha=0.85, zorder=5, edgecolors="white", linewidth=0.8)
        ax1.annotate(f"cross-tech\nn={n:,}", (pred, actual),
                     textcoords="offset points",
                     xytext=(-60, -18), fontsize=7, color=C_ORACLE)

    # legend entries
    legend_handles = [
        Line2D([0], [0], marker="o", color="w", markerfacecolor=C_TMDP,
               markersize=9, label="In-distribution"),
        Line2D([0], [0], marker="D", color="w", markerfacecolor=C_ORACLE,
               markersize=7, label="Cross-technique"),
        Line2D([0], [0], ls="--", color="black", alpha=0.5, label="Perfect calibration"),
        mpatches.Patch(facecolor=C_NEUTRAL, alpha=0.2, label="No-data desert"),
    ]
    ax1.legend(handles=legend_handles, loc="upper left", framealpha=0.9,
               fontsize=7.5)

    ax1.set_xlabel("Mean predicted P(malicious)")
    ax1.set_ylabel("Observed malicious fraction")
    ax1.set_title("(a)  Calibration Reliability Diagram", pad=8)
    ax1.set_xlim(-0.02, 1.05)
    ax1.set_ylim(-0.05, 1.10)

    # ECE annotation
    ax1.text(0.97, 0.08,
             "ECE = 0.0000\nBrier = 0.0000",
             ha="right", va="bottom", fontsize=8.5, color=C_TMDP, fontweight="bold",
             transform=ax1.transAxes,
             bbox=dict(facecolor="#EBF5FB", edgecolor=C_TMDP, pad=5, alpha=0.9))

    # ---- Right: score distribution histogram (log-scale) ------------------
    bin_mids  = [(row["bin_low"] + row["bin_high"]) / 2 for row in indist]
    bin_width = 0.1
    colors_hist = []
    for row in indist:
        m = (row["bin_low"] + row["bin_high"]) / 2
        if m < 0.1:
            colors_hist.append(C_THRESH03)
        elif m > 0.85:
            colors_hist.append(C_DANGER)
        else:
            colors_hist.append(C_THRESH05)

    ax2.bar(bin_mids, in_ns, width=bin_width * 0.85,
            color=colors_hist, edgecolor="white", linewidth=0.5,
            alpha=0.88, label="In-distribution (n=11,935)")
    ax2.set_yscale("log")
    ax2.set_xlabel("P(malicious) score")
    ax2.set_ylabel("Event count  (log scale)")
    ax2.set_title("(b)  Score Distribution — Near-Binary Classifier", pad=8)
    ax2.set_xticks([i / 10 for i in range(11)])
    ax2.set_xticklabels([f"{i/10:.1f}" for i in range(11)])
    ax2.set_xlim(-0.05, 1.05)

    # Annotate the two dense clusters (axes-fraction coords: the log-scale
    # autoscale limits move with the data, so data coords are not stable)
    ax2.text(0.12, 0.84, "Benign cluster\n11,791 events",
             transform=ax2.transAxes,
             ha="center", va="top", fontsize=8, color=C_THRESH03,
             bbox=dict(facecolor="white", edgecolor=C_THRESH03, alpha=0.9, pad=3))
    ax2.text(0.90, 0.28, "Malicious\ncluster\n144 events",
             transform=ax2.transAxes,
             ha="center", va="bottom", fontsize=8, color=C_DANGER,
             bbox=dict(facecolor="white", edgecolor=C_DANGER, alpha=0.9, pad=3))
    ax2.annotate("", xy=(0.42, 0.20), xytext=(0.58, 0.20),
                 xycoords=ax2.transAxes, textcoords=ax2.transAxes,
                 arrowprops=dict(arrowstyle="<->", color="#888888", lw=1.2))
    ax2.text(0.50, 0.17, '"Desert"\n(n=0 — empty)',
             transform=ax2.transAxes,
             ha="center", va="top", fontsize=7.5, color=C_NEUTRAL,
             bbox=dict(facecolor="white", edgecolor=C_NEUTRAL, alpha=0.8, pad=2))

    # p* threshold line
    ax2.axvline(0.40, color=C_TMDP, lw=1.8, ls=":", alpha=0.8)
    ax2.text(0.41, 1200, "p*=0.40", va="center", fontsize=8, color=C_TMDP,
             fontweight="bold")

    # legend entry showing total
    ax2.legend(loc="upper center", framealpha=0.9)

    fig.suptitle("Classifier Calibration — ECE = 0.0000, Fully Binary Output\n"
                 "(In-distribution 5-fold OOF, n=11,935)",
                 fontsize=12, fontweight="bold", y=1.02)
    fig.tight_layout()
    out = FIGURES / "fig4_calibration.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out}")


# ===========================================================================
# Figure 5 — Sequential Block Architecture: Benign Allow Rate Comparison
# ===========================================================================
def fig_sequential_block() -> None:
    data = json.loads(SEQ_AGGREGATE.read_text())

    policies_ordered = [
        ("tmdp-stop-on-first", "T-MDP\nStop-on-First",  C_TMDP2),
        ("threshold-0.5",      "Threshold-0.5\nStop",    C_THRESH05),
        ("oracle-stop",        "Oracle\nStop",            C_ORACLE),
        ("tmdp-sequential",    "T-MDP\nSequential",       C_TMDP),
        ("oracle-sequential",  "Oracle\nSequential",      "#1A9641"),
    ]

    labels   = [p[1] for p in policies_ordered]
    bar_cols  = [p[2] for p in policies_ordered]
    ben_rates = [data[p[0]]["ben_allow_rate"] for p in policies_ordered]
    mal_rates = [data[p[0]]["mal_block_rate"] for p in policies_ordered]

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))
    ax1, ax2  = axes

    # ---- Left: benign allow rate ------------------------------------------
    x    = np.arange(len(labels))
    bars = ax1.bar(x, ben_rates, color=bar_cols, alpha=0.88,
                   edgecolor="white", linewidth=0.8, width=0.62)

    # value labels on bars
    for b, v in zip(bars, ben_rates):
        ax1.text(b.get_x() + b.get_width() / 2,
                 b.get_height() + 0.012,
                 f"{v:.1%}", ha="center", va="bottom",
                 fontsize=8.5, fontweight="bold",
                 color=b.get_facecolor())

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=8.5)
    ax1.set_ylabel("Benign-allow rate")
    ax1.set_title("(a)  Benign Events Correctly Allowed", pad=8)
    ax1.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0%}")
    )
    ax1.set_ylim(0, 1.45)

    # divider between stop and sequential groups
    ax1.axvline(2.5, color="#AAAAAA", lw=1.2, ls="--", alpha=0.6)

    # Group span labels in the top dead space above each group
    ax1.text(1.0, 1.38, "← stop-on-first →",
             ha="center", va="center", fontsize=7.5, color="#888888",
             style="italic")
    ax1.text(3.5, 1.38, "← sequential →",
             ha="center", va="center", fontsize=7.5, color=C_TMDP,
             style="italic", fontweight="bold")

    # Bracket annotation: manual approach — horizontal line + ticks + text box
    stop_x, seq_x = 0, 3
    y_brk = max(ben_rates) + 0.10   # sits above the tallest bar's value label
    # horizontal span line
    ax1.plot([stop_x, seq_x], [y_brk, y_brk], "-", color=C_TMDP, lw=1.8, zorder=6)
    # tick marks at each end
    tick_h = 0.018
    ax1.plot([stop_x, stop_x], [y_brk - tick_h, y_brk], "-", color=C_TMDP, lw=1.8, zorder=6)
    ax1.plot([seq_x,  seq_x],  [y_brk - tick_h, y_brk], "-", color=C_TMDP, lw=1.8, zorder=6)
    # label centred above the line
    ax1.text((stop_x + seq_x) / 2, y_brk + 0.022,
             "+77 pp — structural: 498/498 scenarios improve\n(sign test p = 1.2×10⁻¹⁵⁰, descriptive)",
             ha="center", va="bottom", fontsize=8.5, color=C_TMDP, fontweight="bold",
             bbox=dict(facecolor="white", edgecolor=C_TMDP, alpha=0.95,
                       pad=4, boxstyle="round,pad=0.3"))

    # ---- Right: malicious block rate (safety invariant) -------------------
    bars2 = ax2.bar(x, mal_rates, color=bar_cols, alpha=0.88,
                    edgecolor="white", linewidth=0.8, width=0.62)
    for b, v in zip(bars2, mal_rates):
        ax2.text(b.get_x() + b.get_width() / 2,
                 b.get_height() - 0.015,
                 f"{v:.3f}", ha="center", va="top",
                 fontsize=8.5, fontweight="bold", color="white")

    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=8.5)
    ax2.set_ylabel("Malicious-block rate")
    ax2.set_title("(b)  Malicious Events Correctly Blocked\n(Safety Invariant)", pad=8)
    ax2.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.3f}")
    )
    ax2.set_ylim(0.95, 1.015)

    # safety annotation
    ax2.text(0.5, 0.05,
             "All five plotted policies maintain\nmalicious_block_rate = 1.000\n"
             "T-MDP sequential block: zero safety cost",
             transform=ax2.transAxes, ha="center", va="bottom",
             fontsize=8, color=C_TMDP, fontweight="bold",
             bbox=dict(facecolor="#EBF5FB", edgecolor=C_TMDP, alpha=0.9, pad=5))

    ax2.axvline(2.5, color="#AAAAAA", lw=1.2, ls="--", alpha=0.6)

    fig.suptitle(
        "Sequential Block Architecture: +77 pp Benign Allow Rate at Zero Safety Cost\n"
        "(n=498 scenarios, malicious_frac ∈ {0.1,0.2,0.3}, σ=0.15)",
        fontsize=12, fontweight="bold", y=1.02,
    )
    fig.tight_layout()
    out = FIGURES / "fig5_sequential_block.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out}")


# ===========================================================================
# Main
# ===========================================================================
if __name__ == "__main__":
    import matplotlib.ticker  # ensure available for module-level formatters

    print("Generating figures …")
    fig_pipeline_architecture()
    fig_noise_sweep()
    fig_cost_sweep()
    fig_calibration()
    fig_sequential_block()
    print("\nAll figures saved to docs/figures/")
