"""Render the paper's fault-isolation chart from the retained matrix records."""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import scienceplots  # noqa: F401 -- registers the SciencePlots styles.


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "results_devready" / "raw" / "records.jsonl"
OUTPUT_STEM = PROJECT_ROOT.parent / "paper" / "figures" / "fault_isolation"

DISPLAY_ORDER = (
    "compliant",
    "omit_obligation_on_install",
    "dual_active_on_activate",
    "epoch_guard_converts_commit_to_abort",
    "rewrite_intent_on_install",
    "duplicate_outbox_enqueue",
)
DISPLAY_LABELS = {
    "compliant": "Compliant",
    "omit_obligation_on_install": "Omit P[T]",
    "dual_active_on_activate": "Dual active",
    "epoch_guard_converts_commit_to_abort": "Epoch rewrite",
    "rewrite_intent_on_install": "Intent rewrite",
    "duplicate_outbox_enqueue": "Duplicate enqueue",
}
BASELINE = "#0F4D92"
FAULT = "#B64342"
NEUTRAL = "#767676"


def _load_records() -> dict[str, list[dict[str, object]]]:
    records: dict[str, list[dict[str, object]]] = defaultdict(list)
    for line in DATA_PATH.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        records[str(record["variant"])].append(record)
    missing = set(DISPLAY_ORDER).difference(records)
    if missing:
        raise ValueError(f"missing variants: {sorted(missing)}")
    return records


def _witness_depth(record: dict[str, object]) -> int | None:
    witness = record.get("violation_witness")
    if not isinstance(witness, dict):
        return None
    depth = witness.get("depth")
    return depth if isinstance(depth, int) else None


def main() -> None:
    records = _load_records()

    # This is an exhaustive configuration matrix, not a sampled experiment:
    # each point is retained rather than summarized as a statistical estimate.
    with plt.style.context(["science", "ieee", "no-latex"]):
        plt.rcParams.update(
            {
                "font.family": "sans-serif",
                "font.sans-serif": ["Arial", "DejaVu Sans", "Liberation Sans"],
                "svg.fonttype": "none",
                "pdf.fonttype": 42,
                "font.size": 7.2,
                "axes.labelsize": 7.2,
                "xtick.labelsize": 6.6,
                "ytick.labelsize": 6.6,
                "axes.linewidth": 0.7,
            }
        )
        fig, (states_ax, witness_ax) = plt.subplots(
            2,
            1,
            figsize=(3.45, 1.92),
            gridspec_kw={"height_ratios": (1.08, 0.92)},
        )
        fig.subplots_adjust(
            left=0.265,
            right=0.988,
            bottom=0.165,
            top=0.925,
            hspace=0.52,
        )

        y_positions = np.arange(len(DISPLAY_ORDER))[::-1]
        jitter = np.linspace(-0.11, 0.11, 12)
        for y, variant in zip(y_positions, DISPLAY_ORDER):
            variant_records = records[variant]
            states = np.array(
                [int(record["states_explored"]) for record in variant_records]
            )
            color = BASELINE if variant == "compliant" else FAULT
            marker = "o" if variant == "compliant" else "s"
            states_ax.hlines(y, states.min(), states.max(), color=color, lw=1.5)
            states_ax.scatter(
                states,
                y + jitter,
                s=13,
                marker=marker,
                color=color,
                edgecolor="white",
                linewidth=0.35,
                zorder=3,
            )
            states_ax.text(
                states.max() + 5,
                y,
                f"{states.min()}–{states.max()}",
                va="center",
                color=color,
                fontsize=6.2,
            )

        states_ax.set(
            xlim=(0, 390),
            xticks=(0, 100, 200, 300),
            yticks=y_positions,
            yticklabels=[DISPLAY_LABELS[variant] for variant in DISPLAY_ORDER],
        )
        states_ax.grid(axis="x", color="#D8D8D8", lw=0.55, zorder=0)
        states_ax.tick_params(axis="y", length=0)
        states_ax.set_title("a  State-space coverage", loc="left", fontsize=8.2, fontweight="bold")

        fault_order = DISPLAY_ORDER[1:]
        fault_positions = np.arange(len(fault_order))[::-1]
        for y, variant in zip(fault_positions, fault_order):
            variant_records = records[variant]
            applicable = sum(
                bool(record["mutant_applicable"]) for record in variant_records
            )
            witnesses = sum(
                bool(record["expected_witness_found"]) for record in variant_records
            )
            depths = sorted(
                {
                    depth
                    for record in variant_records
                    if (depth := _witness_depth(record)) is not None
                }
            )
            if len(depths) != 1:
                raise ValueError(f"non-unique witness depth for {variant}: {depths}")
            depth = depths[0]
            witness_ax.hlines(y, 0, depth, color="#D8D8D8", lw=1.0, zorder=0)
            witness_ax.plot(depth, y, marker="s", ms=5.7, color=FAULT)
            witness_ax.text(
                depth + 0.26,
                y,
                f"{witnesses}/{applicable}",
                va="center",
                fontsize=6.6,
                color=FAULT,
            )

        witness_ax.set(
            xlim=(-0.1, 11.4),
            xticks=(0, 2, 4, 6, 8, 10),
            yticks=fault_positions,
            yticklabels=[DISPLAY_LABELS[variant] for variant in fault_order],
            xlabel="Shortest counterexample depth",
        )
        witness_ax.grid(axis="x", color="#D8D8D8", lw=0.55, zorder=0)
        witness_ax.tick_params(axis="y", length=0)
        witness_ax.set_title("b  Targeted fault detection", loc="left", fontsize=8.2, fontweight="bold")
        OUTPUT_STEM.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(OUTPUT_STEM.with_suffix(".pdf"))
        fig.savefig(OUTPUT_STEM.with_suffix(".svg"))
        fig.savefig(OUTPUT_STEM.with_suffix(".png"), dpi=600)
        fig.savefig(OUTPUT_STEM.with_suffix(".tiff"), dpi=600)


if __name__ == "__main__":
    main()
