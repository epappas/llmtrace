#!/usr/bin/env python3
"""Post-process streaming experiment JSON results into ArXiv-ready figures and tables.

Reads JSON output from Experiments A-D (truncation, boundary, checkpoint,
recalibration) and generates:
  - 7 PDF vector figures (matplotlib, 300 DPI, booktabs-compatible sizing)
  - 6 LaTeX tables (booktabs format)

Input JSON schemas match the Rust structs in benchmarks/src/experiments/types.rs.

Requirements:
  pip install pandas matplotlib numpy

Usage:
  python benchmarks/scripts/analyze_experiments.py --input-dir benchmarks/results --output-dir benchmarks/analysis
"""

import argparse
import json
import sys
import warnings
from pathlib import Path
from typing import Optional

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OUTPUT_SUITES = {"bipia", "injecagent", "safeguard_v2", "deepset_v2"}

TRUNCATION_FILE = "truncation_experiment.json"
BOUNDARY_FILE = "boundary_experiment.json"
CHECKPOINT_FILE = "checkpoint_experiment.json"
RECALIBRATION_FILE = "recalibration_experiment.json"

# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------


def setup_style() -> None:
    """Configure matplotlib for ArXiv-quality output."""
    matplotlib.use("Agg")
    plt.rcParams.update({
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "font.size": 12,
        "axes.labelsize": 12,
        "axes.titlesize": 13,
        "legend.fontsize": 10,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "figure.figsize": (7, 4.5),
        "axes.grid": True,
        "grid.alpha": 0.3,
        "lines.linewidth": 1.5,
        "lines.markersize": 5,
        "font.family": "serif",
        "text.usetex": False,
    })


# ---------------------------------------------------------------------------
# Direction mapping (mirrors Rust suite_direction in types.rs:14-18)
# ---------------------------------------------------------------------------


def suite_direction(suite: str) -> str:
    """Classify a suite as 'input' or 'output' direction."""
    if suite in OUTPUT_SUITES:
        return "output"
    return "input"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def save_fig(fig: plt.Figure, path: Path) -> None:
    """Save figure as PDF with tight layout and close it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(str(path), format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"  saved {path}")


def latex_table(
    df: pd.DataFrame,
    caption: str,
    label: str,
    fmt: Optional[dict] = None,
) -> str:
    """Render a DataFrame as a booktabs LaTeX table string."""
    if fmt is None:
        fmt = {}

    formatted = df.copy()
    for col, f in fmt.items():
        if col in formatted.columns:
            formatted[col] = formatted[col].map(f)

    header = " & ".join(formatted.columns)
    rows = []
    for _, row in formatted.iterrows():
        rows.append(" & ".join(str(v) for v in row.values))

    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        r"\begin{tabular}{" + "l" * len(formatted.columns) + "}",
        r"\toprule",
        header + r" \\",
        r"\midrule",
    ]
    for r in rows:
        lines.append(r + r" \\")
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return "\n".join(lines)


def save_table(content: str, path: Path) -> None:
    """Write a LaTeX table string to a .tex file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  saved {path}")


def weighted_mean(group: pd.DataFrame, value_col: str, weight_col: str) -> float:
    """Compute sample-count weighted mean."""
    w = group[weight_col].values.astype(float)
    v = group[value_col].values.astype(float)
    total = w.sum()
    if total == 0:
        return 0.0
    return float(np.average(v, weights=w))


def pct(x: float) -> str:
    """Format float as percentage string."""
    return f"{x * 100:.1f}"


def f2(x: float) -> str:
    """Format float to 2 decimal places."""
    return f"{x:.2f}"


def f3(x: float) -> str:
    """Format float to 3 decimal places."""
    return f"{x:.3f}"


def f4(x: float) -> str:
    """Format float to 4 decimal places."""
    return f"{x:.4f}"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_json(path: Path) -> Optional[dict]:
    """Load a JSON file, returning None if missing or invalid."""
    if not path.exists():
        warnings.warn(f"File not found, skipping: {path}")
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        warnings.warn(f"Failed to load {path}: {e}")
        return None


def load_truncation(input_dir: Path) -> Optional[tuple[pd.DataFrame, pd.DataFrame]]:
    """Load Experiment A: truncation results.

    Returns (level_metrics_df, samples_df) or None.
    """
    data = load_json(input_dir / TRUNCATION_FILE)
    if data is None:
        return None

    level_metrics = data.get("level_metrics", [])
    sample_results = data.get("sample_results", [])

    if not level_metrics and not sample_results:
        warnings.warn("Truncation experiment has no data")
        return None

    lm_df = pd.DataFrame(level_metrics)
    sr_df = pd.DataFrame()
    if sample_results:
        rows = []
        for s in sample_results:
            row = {
                "sample_id": s["sample_id"],
                "suite": s.get("suite", ""),
                "actual_malicious": s["actual_malicious"],
                "original_char_len": s["original_char_len"],
                "truncation_fraction": s["truncation_fraction"],
                "truncated_char_len": s["truncated_char_len"],
                "detector": s["detector"],
                "injection_score": s["scores"]["injection_score"],
                "predicted_label": s["scores"]["predicted_label"],
                "inference_us": s["inference_us"],
            }
            rows.append(row)
        sr_df = pd.DataFrame(rows)

    if not lm_df.empty:
        lm_df["direction"] = lm_df["suite"].map(suite_direction)
    if not sr_df.empty:
        sr_df["direction"] = sr_df["suite"].map(suite_direction)

    return lm_df, sr_df


def load_boundary(input_dir: Path) -> Optional[pd.DataFrame]:
    """Load Experiment B: boundary detection results.

    Flattens the nested boundaries into one row per (sample, threshold).
    """
    data = load_json(input_dir / BOUNDARY_FILE)
    if data is None:
        return None

    samples = data.get("sample_results", [])
    if not samples:
        warnings.warn("Boundary experiment has no sample data")
        return None

    rows = []
    for s in samples:
        for bt in s.get("boundaries", []):
            rows.append({
                "sample_id": s["sample_id"],
                "suite": s.get("suite", ""),
                "original_char_len": s["original_char_len"],
                "detector": s["detector"],
                "full_text_score": s["full_text_score"],
                "inference_calls": s["inference_calls"],
                "threshold": bt["threshold"],
                "boundary_fraction": bt.get("boundary_fraction"),
                "boundary_char_pos": bt.get("boundary_char_pos"),
            })

    if not rows:
        warnings.warn("Boundary experiment has no boundary data")
        return None

    df = pd.DataFrame(rows)
    df["direction"] = df["suite"].map(suite_direction)
    return df


def load_checkpoint(input_dir: Path) -> Optional[tuple[pd.DataFrame, pd.DataFrame]]:
    """Load Experiment C: checkpoint strategy results.

    Returns (strategy_metrics_df, samples_df) or None.
    """
    data = load_json(input_dir / CHECKPOINT_FILE)
    if data is None:
        return None

    strategy_metrics = data.get("strategy_metrics", [])
    sample_results = data.get("sample_results", [])

    if not strategy_metrics and not sample_results:
        warnings.warn("Checkpoint experiment has no data")
        return None

    sm_df = pd.DataFrame(strategy_metrics)
    sr_df = pd.DataFrame(sample_results) if sample_results else pd.DataFrame()

    if not sm_df.empty:
        sm_df["direction"] = sm_df["suite"].map(suite_direction)
    if not sr_df.empty:
        sr_df["direction"] = sr_df["suite"].map(suite_direction)

    return sm_df, sr_df


def load_recalibration(input_dir: Path) -> Optional[dict]:
    """Load Experiment D: recalibration comparison results."""
    return load_json(input_dir / RECALIBRATION_FILE)


# ---------------------------------------------------------------------------
# Figure 1: Degradation curves (Exp A level_metrics)
# ---------------------------------------------------------------------------


def plot_degradation_curves(lm_df: pd.DataFrame, output_dir: Path) -> None:
    """Plot TPR and F1 vs truncation fraction per detector."""
    detectors = sorted(lm_df["detector"].unique())
    n_det = len(detectors)
    if n_det == 0:
        return

    fig, axes = plt.subplots(n_det, 2, figsize=(10, 3.5 * n_det), squeeze=False)

    for i, det in enumerate(detectors):
        det_df = lm_df[lm_df["detector"] == det]
        suites = sorted(det_df["suite"].unique())

        for suite in suites:
            sub = det_df[det_df["suite"] == suite].sort_values("truncation_fraction")
            axes[i, 0].plot(sub["truncation_fraction"], sub["tpr"], marker="o", label=suite)
            axes[i, 1].plot(sub["truncation_fraction"], sub["f1"], marker="s", label=suite)

        axes[i, 0].set_ylabel("TPR")
        axes[i, 0].set_title(f"{det} -- TPR vs Truncation")
        axes[i, 0].set_xlabel("Truncation Fraction")
        axes[i, 0].legend(fontsize=7, ncol=2)
        axes[i, 0].set_ylim(-0.05, 1.05)

        axes[i, 1].set_ylabel("F1")
        axes[i, 1].set_title(f"{det} -- F1 vs Truncation")
        axes[i, 1].set_xlabel("Truncation Fraction")
        axes[i, 1].legend(fontsize=7, ncol=2)
        axes[i, 1].set_ylim(-0.05, 1.05)

    save_fig(fig, output_dir / "figures" / "fig1_degradation_curves.pdf")


# ---------------------------------------------------------------------------
# Figure 2: Direction comparison (Exp A level_metrics)
# ---------------------------------------------------------------------------


def plot_direction_comparison(lm_df: pd.DataFrame, output_dir: Path) -> None:
    """Plot input vs output direction degradation in a 2x2 grid."""
    detectors = sorted(lm_df["detector"].unique())
    if not detectors:
        return

    metrics = ["tpr", "f1"]
    directions = ["input", "output"]

    fig, axes = plt.subplots(2, 2, figsize=(10, 8), squeeze=False)

    for col_idx, metric in enumerate(metrics):
        for row_idx, direction in enumerate(directions):
            ax = axes[row_idx, col_idx]
            sub = lm_df[lm_df["direction"] == direction]
            if sub.empty:
                ax.set_title(f"{direction} -- {metric.upper()} (no data)")
                continue

            for det in detectors:
                det_sub = sub[sub["detector"] == det]
                # aggregate across suites with sample-weighted mean
                agg = det_sub.groupby("truncation_fraction").apply(
                    lambda g: weighted_mean(g, metric, "num_samples"),
                    include_groups=False,
                ).reset_index()
                agg.columns = ["truncation_fraction", metric]
                agg = agg.sort_values("truncation_fraction")
                ax.plot(agg["truncation_fraction"], agg[metric], marker="o", label=det)

            ax.set_title(f"{direction.title()} direction -- {metric.upper()}")
            ax.set_xlabel("Truncation Fraction")
            ax.set_ylabel(metric.upper())
            ax.set_ylim(-0.05, 1.05)
            ax.legend(fontsize=8)

    save_fig(fig, output_dir / "figures" / "fig2_direction_comparison.pdf")


# ---------------------------------------------------------------------------
# Figure 3: Score distributions (Exp A sample_results)
# ---------------------------------------------------------------------------


def plot_score_distributions(sr_df: pd.DataFrame, output_dir: Path) -> None:
    """Violin plot of malicious vs benign scores per truncation level."""
    detectors = sorted(sr_df["detector"].unique())
    levels = sorted(sr_df["truncation_fraction"].unique())
    n_det = len(detectors)
    if n_det == 0 or not levels:
        return

    fig, axes = plt.subplots(n_det, 1, figsize=(10, 3.5 * n_det), squeeze=False)

    for i, det in enumerate(detectors):
        ax = axes[i, 0]
        det_df = sr_df[sr_df["detector"] == det]

        positions_mal = []
        positions_ben = []
        data_mal = []
        data_ben = []

        for j, lvl in enumerate(levels):
            lvl_df = det_df[det_df["truncation_fraction"] == lvl]
            mal = lvl_df[lvl_df["actual_malicious"]]["injection_score"].values
            ben = lvl_df[~lvl_df["actual_malicious"]]["injection_score"].values
            if len(mal) > 1:
                data_mal.append(mal)
                positions_mal.append(j * 3)
            if len(ben) > 1:
                data_ben.append(ben)
                positions_ben.append(j * 3 + 1)

        if data_mal:
            vp1 = ax.violinplot(data_mal, positions=positions_mal, showmedians=True)
            for body in vp1["bodies"]:
                body.set_facecolor("tab:red")
                body.set_alpha(0.6)
        if data_ben:
            vp2 = ax.violinplot(data_ben, positions=positions_ben, showmedians=True)
            for body in vp2["bodies"]:
                body.set_facecolor("tab:blue")
                body.set_alpha(0.6)

        tick_positions = [j * 3 + 0.5 for j in range(len(levels))]
        ax.set_xticks(tick_positions)
        ax.set_xticklabels([f"{pct(l)}%" for l in levels])
        ax.set_xlabel("Truncation Level")
        ax.set_ylabel("Injection Score")
        ax.set_title(f"{det} -- Score Distributions")
        # manual legend
        from matplotlib.patches import Patch
        ax.legend(
            handles=[Patch(facecolor="tab:red", alpha=0.6, label="Malicious"),
                     Patch(facecolor="tab:blue", alpha=0.6, label="Benign")],
            fontsize=8,
        )

    save_fig(fig, output_dir / "figures" / "fig3_score_distributions.pdf")


# ---------------------------------------------------------------------------
# Figure 4: Boundary distributions (Exp B)
# ---------------------------------------------------------------------------


def plot_boundary_distributions(bnd_df: pd.DataFrame, output_dir: Path) -> None:
    """Histogram of boundary_fraction per detector per threshold."""
    # Only rows where boundary was found
    found = bnd_df[bnd_df["boundary_fraction"].notna()].copy()
    if found.empty:
        warnings.warn("No boundary fractions found, skipping fig4")
        return

    detectors = sorted(found["detector"].unique())
    thresholds = sorted(found["threshold"].unique())
    n_det = len(detectors)

    fig, axes = plt.subplots(n_det, len(thresholds),
                             figsize=(4 * len(thresholds), 3.5 * n_det),
                             squeeze=False)

    for i, det in enumerate(detectors):
        for j, thr in enumerate(thresholds):
            ax = axes[i, j]
            sub = found[(found["detector"] == det) & (found["threshold"] == thr)]
            if sub.empty:
                ax.set_title(f"{det} @ {pct(thr)}% (no data)")
                continue
            ax.hist(sub["boundary_fraction"].values, bins=20, range=(0, 1),
                    color="tab:green", alpha=0.7, edgecolor="black", linewidth=0.5)
            median_val = sub["boundary_fraction"].median()
            ax.axvline(median_val, color="tab:red", linestyle="--", linewidth=1.2,
                       label=f"median={f2(median_val)}")
            ax.set_title(f"{det} @ threshold={f2(thr)}")
            ax.set_xlabel("Boundary Fraction")
            ax.set_ylabel("Count")
            ax.legend(fontsize=8)

    save_fig(fig, output_dir / "figures" / "fig4_boundary_distributions.pdf")


# ---------------------------------------------------------------------------
# Figure 5: Pareto frontier (Exp C strategy_metrics)
# ---------------------------------------------------------------------------


def plot_pareto_frontier(sm_df: pd.DataFrame, output_dir: Path) -> None:
    """Scatter: mean inference calls (x) vs TPR (y), Pareto points highlighted."""
    detectors = sorted(sm_df["detector"].unique())
    n_det = len(detectors)
    if n_det == 0:
        return

    fig, axes = plt.subplots(1, n_det, figsize=(5 * n_det, 4.5), squeeze=False)

    for i, det in enumerate(detectors):
        ax = axes[0, i]
        det_df = sm_df[sm_df["detector"] == det]

        # aggregate across suites per strategy
        agg = det_df.groupby("strategy").agg(
            mean_inference_calls=("mean_inference_calls", "mean"),
            tpr=("tpr", "mean"),
            is_pareto=("is_pareto", "any"),
        ).reset_index()

        non_pareto = agg[~agg["is_pareto"]]
        pareto = agg[agg["is_pareto"]]

        ax.scatter(non_pareto["mean_inference_calls"], non_pareto["tpr"],
                   color="tab:gray", alpha=0.6, s=40, label="Non-Pareto")
        ax.scatter(pareto["mean_inference_calls"], pareto["tpr"],
                   color="tab:red", s=80, marker="*", zorder=5, label="Pareto")

        # connect Pareto points
        if not pareto.empty:
            pareto_sorted = pareto.sort_values("mean_inference_calls")
            ax.plot(pareto_sorted["mean_inference_calls"], pareto_sorted["tpr"],
                    color="tab:red", linestyle="--", alpha=0.5)

        # label strategies
        for _, row in agg.iterrows():
            ax.annotate(row["strategy"], (row["mean_inference_calls"], row["tpr"]),
                        fontsize=7, ha="left", va="bottom",
                        xytext=(3, 3), textcoords="offset points")

        ax.set_xlabel("Mean Inference Calls")
        ax.set_ylabel("TPR")
        ax.set_title(f"{det} -- Pareto Frontier")
        ax.legend(fontsize=8)

    save_fig(fig, output_dir / "figures" / "fig5_pareto_frontier.pdf")


# ---------------------------------------------------------------------------
# Figure 6: Recalibration lift (Exp D)
# ---------------------------------------------------------------------------


def plot_recalibration_lift(recal: dict, output_dir: Path) -> None:
    """Grouped bars: streaming vs naive F1 per truncation level."""
    per_level = recal.get("per_level", [])
    if not per_level:
        warnings.warn("No per_level data for recalibration, skipping fig6")
        return

    fractions = [lvl["truncation_fraction"] for lvl in per_level]
    streaming_f1 = [lvl["streaming_metrics"]["f1"] for lvl in per_level]
    naive_f1 = [lvl["naive_metrics"]["f1"] for lvl in per_level]

    x = np.arange(len(fractions))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(x - width / 2, streaming_f1, width, label="Streaming-aware", color="tab:blue")
    ax.bar(x + width / 2, naive_f1, width, label="Naive (global)", color="tab:orange")

    ax.set_xlabel("Truncation Fraction")
    ax.set_ylabel("F1 Score")
    ax.set_title("Recalibration: Streaming vs Naive F1")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{pct(f)}%" for f in fractions])
    ax.set_ylim(0, 1.05)
    ax.legend()

    save_fig(fig, output_dir / "figures" / "fig6_recalibration_lift.pdf")


# ---------------------------------------------------------------------------
# Figure 7: Weight evolution (Exp D)
# ---------------------------------------------------------------------------


def plot_weight_evolution(recal: dict, output_dir: Path) -> None:
    """Line plot: detector weights across truncation levels."""
    per_level = recal.get("per_level", [])
    detector_names = recal.get("detector_names", [])
    if not per_level or not detector_names:
        warnings.warn("No weight data for recalibration, skipping fig7")
        return

    fractions = [lvl["truncation_fraction"] for lvl in per_level]

    fig, ax = plt.subplots(figsize=(8, 4.5))

    for idx, det_name in enumerate(detector_names):
        weights = [lvl["streaming_weights"]["detector_weights"][idx] for lvl in per_level]
        ax.plot(fractions, weights, marker="o", label=det_name)

    # bias line
    biases = [lvl["streaming_weights"]["bias"] for lvl in per_level]
    ax.plot(fractions, biases, marker="x", linestyle="--", color="black", label="bias")

    ax.set_xlabel("Truncation Fraction")
    ax.set_ylabel("Weight")
    ax.set_title("Streaming Weight Evolution Across Truncation Levels")
    ax.legend()

    save_fig(fig, output_dir / "figures" / "fig7_weight_evolution.pdf")


# ---------------------------------------------------------------------------
# Table 1: Baseline metrics (Exp A level_metrics at 100%)
# ---------------------------------------------------------------------------


def table_baseline_metrics(lm_df: pd.DataFrame, output_dir: Path) -> None:
    """Full-text (100%) metrics per detector x suite."""
    full = lm_df[lm_df["truncation_fraction"] == 1.0].copy()
    if full.empty:
        warnings.warn("No full-text metrics, skipping tab1")
        return

    cols = ["detector", "suite", "accuracy", "tpr", "fpr", "f1", "tpr_at_1pct_fpr"]
    table_df = full[cols].sort_values(["detector", "suite"]).reset_index(drop=True)

    fmt = {c: f3 for c in ["accuracy", "tpr", "fpr", "f1", "tpr_at_1pct_fpr"]}
    content = latex_table(
        table_df.rename(columns={
            "detector": "Detector", "suite": "Suite", "accuracy": "Acc",
            "tpr": "TPR", "fpr": "FPR", "f1": "F1", "tpr_at_1pct_fpr": "TPR@1\\%FPR",
        }),
        caption="Baseline (full-text) detection metrics per detector and suite.",
        label="tab:baseline",
        fmt={"Acc": f3, "TPR": f3, "FPR": f3, "F1": f3, "TPR@1\\%FPR": f3},
    )
    save_table(content, output_dir / "tables" / "tab1_baseline_metrics.tex")


# ---------------------------------------------------------------------------
# Table 2: Truncation comparison (Exp A)
# ---------------------------------------------------------------------------


def table_truncation_comparison(lm_df: pd.DataFrame, output_dir: Path) -> None:
    """Key truncation levels (20/60/100%) with degradation delta."""
    key_levels = [0.2, 0.6, 1.0]
    sub = lm_df[lm_df["truncation_fraction"].isin(key_levels)].copy()
    if sub.empty:
        warnings.warn("No data for key truncation levels, skipping tab2")
        return

    # Aggregate across suites per (detector, level) with sample-weighted mean
    rows = []
    for (det, frac), g in sub.groupby(["detector", "truncation_fraction"]):
        rows.append({
            "Detector": det,
            "Level": f"{pct(frac)}%",
            "TPR": weighted_mean(g, "tpr", "num_samples"),
            "F1": weighted_mean(g, "f1", "num_samples"),
            "FPR": weighted_mean(g, "fpr", "num_samples"),
        })
    agg_df = pd.DataFrame(rows)

    # Add delta column (difference from 100%)
    deltas = []
    for _, row in agg_df.iterrows():
        if row["Level"] == "100.0%":
            deltas.append("")
        else:
            full = agg_df[
                (agg_df["Detector"] == row["Detector"]) & (agg_df["Level"] == "100.0%")
            ]
            if full.empty:
                deltas.append("")
            else:
                delta_f1 = row["F1"] - full.iloc[0]["F1"]
                sign = "+" if delta_f1 >= 0 else ""
                deltas.append(f"{sign}{delta_f1 * 100:.1f}pp")
    agg_df["F1 Delta"] = deltas

    fmt = {"TPR": f3, "F1": f3, "FPR": f3}
    content = latex_table(
        agg_df, caption="Detection metrics at key truncation levels (sample-weighted across suites).",
        label="tab:truncation", fmt=fmt,
    )
    save_table(content, output_dir / "tables" / "tab2_truncation_comparison.tex")


# ---------------------------------------------------------------------------
# Table 3: Boundary summary (Exp B)
# ---------------------------------------------------------------------------


def table_boundary_summary(bnd_df: pd.DataFrame, output_dir: Path) -> None:
    """Median boundary fraction per detector x threshold."""
    found = bnd_df[bnd_df["boundary_fraction"].notna()].copy()
    if found.empty:
        warnings.warn("No boundary data, skipping tab3")
        return

    agg = found.groupby(["detector", "threshold"]).agg(
        median_frac=("boundary_fraction", "median"),
        count=("boundary_fraction", "count"),
    ).reset_index()

    # Pivot: rows=detector, cols=threshold
    pivot = agg.pivot(index="detector", columns="threshold", values="median_frac")
    pivot.columns = [f"Thr={f2(c)}" for c in pivot.columns]
    pivot = pivot.reset_index().rename(columns={"detector": "Detector"})

    fmt = {c: f3 for c in pivot.columns if c.startswith("Thr=")}
    content = latex_table(
        pivot,
        caption="Median boundary fraction (text proportion needed) per detector and confidence threshold.",
        label="tab:boundary",
        fmt=fmt,
    )
    save_table(content, output_dir / "tables" / "tab3_boundary_summary.tex")


# ---------------------------------------------------------------------------
# Table 4: Checkpoint strategies (Exp C)
# ---------------------------------------------------------------------------


def table_checkpoint_strategies(sm_df: pd.DataFrame, output_dir: Path) -> None:
    """All strategies with Pareto markers, aggregated across suites."""
    if sm_df.empty:
        return

    agg = sm_df.groupby(["detector", "strategy"]).agg(
        num_checkpoints=("num_checkpoints", "first"),
        tpr=("tpr", "mean"),
        fpr=("fpr", "mean"),
        mean_calls=("mean_inference_calls", "mean"),
        mean_latency=("mean_detection_latency", "mean"),
        is_pareto=("is_pareto", "any"),
    ).reset_index()

    agg["Pareto"] = agg["is_pareto"].map({True: "Y", False: ""})
    table_df = agg[["detector", "strategy", "num_checkpoints", "tpr", "fpr",
                     "mean_calls", "mean_latency", "Pareto"]].copy()
    table_df.columns = ["Detector", "Strategy", "Checkpoints", "TPR", "FPR",
                        "Avg Calls", "Avg Latency", "Pareto"]
    table_df = table_df.sort_values(["Detector", "Avg Calls"]).reset_index(drop=True)

    fmt = {"TPR": f3, "FPR": f3, "Avg Calls": f2, "Avg Latency": f3}
    content = latex_table(
        table_df,
        caption="Checkpoint strategy comparison (aggregated across suites).",
        label="tab:checkpoint",
        fmt=fmt,
    )
    save_table(content, output_dir / "tables" / "tab4_checkpoint_strategies.tex")


# ---------------------------------------------------------------------------
# Table 5: Recalibration comparison (Exp D)
# ---------------------------------------------------------------------------


def table_recalibration_comparison(recal: dict, output_dir: Path) -> None:
    """Streaming vs naive per truncation level + lift."""
    per_level = recal.get("per_level", [])
    if not per_level:
        warnings.warn("No recalibration per-level data, skipping tab5")
        return

    rows = []
    for lvl in per_level:
        frac = lvl["truncation_fraction"]
        sm = lvl["streaming_metrics"]
        nm = lvl["naive_metrics"]
        lift = sm["f1"] - nm["f1"]
        sign = "+" if lift >= 0 else ""
        rows.append({
            "Level": f"{pct(frac)}%",
            "Stream F1": f3(sm["f1"]),
            "Stream TPR": f3(sm["tpr"]),
            "Naive F1": f3(nm["f1"]),
            "Naive TPR": f3(nm["tpr"]),
            "F1 Lift": f"{sign}{lift * 100:.1f}pp",
        })

    table_df = pd.DataFrame(rows)
    content = latex_table(
        table_df,
        caption="Streaming-aware vs naive recalibration per truncation level.",
        label="tab:recalibration",
    )
    save_table(content, output_dir / "tables" / "tab5_recalibration_comparison.tex")


# ---------------------------------------------------------------------------
# Table 6: Direction analysis (Exp A)
# ---------------------------------------------------------------------------


def table_direction_analysis(lm_df: pd.DataFrame, output_dir: Path) -> None:
    """Input vs output aggregated metrics at key truncation levels."""
    key_levels = [0.2, 0.6, 1.0]
    sub = lm_df[lm_df["truncation_fraction"].isin(key_levels)].copy()
    if sub.empty:
        warnings.warn("No data for direction analysis, skipping tab6")
        return

    rows = []
    for (det, direction, frac), g in sub.groupby(["detector", "direction", "truncation_fraction"]):
        rows.append({
            "Detector": det,
            "Direction": direction,
            "Level": f"{pct(frac)}%",
            "TPR": weighted_mean(g, "tpr", "num_samples"),
            "F1": weighted_mean(g, "f1", "num_samples"),
            "FPR": weighted_mean(g, "fpr", "num_samples"),
            "Samples": int(g["num_samples"].sum()),
        })
    table_df = pd.DataFrame(rows)
    table_df = table_df.sort_values(["Detector", "Direction", "Level"]).reset_index(drop=True)

    fmt = {"TPR": f3, "F1": f3, "FPR": f3}
    content = latex_table(
        table_df,
        caption="Detection metrics by injection direction at key truncation levels.",
        label="tab:direction",
        fmt=fmt,
    )
    save_table(content, output_dir / "tables" / "tab6_direction_analysis.tex")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ArXiv-ready figures and tables from experiment results."
    )
    parser.add_argument(
        "--input-dir", type=str, default=None,
        help="Directory containing experiment JSON files (default: benchmarks/results relative to script)",
    )
    parser.add_argument(
        "--output-dir", type=str, default=None,
        help="Directory for output figures/ and tables/ (default: benchmarks/analysis relative to script)",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    benchmarks_dir = script_dir.parent

    input_dir = Path(args.input_dir) if args.input_dir else benchmarks_dir / "results"
    output_dir = Path(args.output_dir) if args.output_dir else benchmarks_dir / "analysis"

    input_dir = input_dir.resolve()
    output_dir = output_dir.resolve()

    print(f"Input dir:  {input_dir}")
    print(f"Output dir: {output_dir}")

    setup_style()

    # --- Experiment A: Truncation ---
    print("\n--- Experiment A: Truncation ---")
    trunc = load_truncation(input_dir)
    if trunc is not None:
        lm_df, sr_df = trunc
        print(f"  level_metrics: {len(lm_df)} rows, samples: {len(sr_df)} rows")

        try:
            if not lm_df.empty:
                plot_degradation_curves(lm_df, output_dir)
        except Exception as e:
            warnings.warn(f"fig1 failed: {e}")

        try:
            if not lm_df.empty:
                plot_direction_comparison(lm_df, output_dir)
        except Exception as e:
            warnings.warn(f"fig2 failed: {e}")

        try:
            if not sr_df.empty:
                plot_score_distributions(sr_df, output_dir)
        except Exception as e:
            warnings.warn(f"fig3 failed: {e}")

        try:
            if not lm_df.empty:
                table_baseline_metrics(lm_df, output_dir)
        except Exception as e:
            warnings.warn(f"tab1 failed: {e}")

        try:
            if not lm_df.empty:
                table_truncation_comparison(lm_df, output_dir)
        except Exception as e:
            warnings.warn(f"tab2 failed: {e}")

        try:
            if not lm_df.empty:
                table_direction_analysis(lm_df, output_dir)
        except Exception as e:
            warnings.warn(f"tab6 failed: {e}")
    else:
        print("  skipped (no data)")

    # --- Experiment B: Boundary ---
    print("\n--- Experiment B: Boundary ---")
    bnd_df = load_boundary(input_dir)
    if bnd_df is not None:
        print(f"  boundary samples: {len(bnd_df)} rows")

        try:
            plot_boundary_distributions(bnd_df, output_dir)
        except Exception as e:
            warnings.warn(f"fig4 failed: {e}")

        try:
            table_boundary_summary(bnd_df, output_dir)
        except Exception as e:
            warnings.warn(f"tab3 failed: {e}")
    else:
        print("  skipped (no data)")

    # --- Experiment C: Checkpoint ---
    print("\n--- Experiment C: Checkpoint ---")
    ckpt = load_checkpoint(input_dir)
    if ckpt is not None:
        sm_df, ckpt_sr_df = ckpt
        print(f"  strategy_metrics: {len(sm_df)} rows, samples: {len(ckpt_sr_df)} rows")

        try:
            if not sm_df.empty:
                plot_pareto_frontier(sm_df, output_dir)
        except Exception as e:
            warnings.warn(f"fig5 failed: {e}")

        try:
            if not sm_df.empty:
                table_checkpoint_strategies(sm_df, output_dir)
        except Exception as e:
            warnings.warn(f"tab4 failed: {e}")
    else:
        print("  skipped (no data)")

    # --- Experiment D: Recalibration ---
    print("\n--- Experiment D: Recalibration ---")
    recal = load_recalibration(input_dir)
    if recal is not None:
        n_levels = len(recal.get("per_level", []))
        print(f"  per_level: {n_levels} levels")

        try:
            plot_recalibration_lift(recal, output_dir)
        except Exception as e:
            warnings.warn(f"fig6 failed: {e}")

        try:
            plot_weight_evolution(recal, output_dir)
        except Exception as e:
            warnings.warn(f"fig7 failed: {e}")

        try:
            table_recalibration_comparison(recal, output_dir)
        except Exception as e:
            warnings.warn(f"tab5 failed: {e}")
    else:
        print("  skipped (no data)")

    print("\nDone.")


if __name__ == "__main__":
    main()
