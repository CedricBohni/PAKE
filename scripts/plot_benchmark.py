"""Draw the login-time chart from docs/benchmark.json, in a light and a dark version.

    uv run python scripts/plot_benchmark.py       # writes docs/benchmark-light.png and -dark.png

The README shows the right one with <picture>/prefers-color-scheme.
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

INSTALLED = {font.name for font in font_manager.fontManager.ttflist}
FONT = next(name for name in ("Segoe UI", "Helvetica Neue", "Arial", "DejaVu Sans") if name in INSTALLED)

DOCS = Path(__file__).resolve().parent.parent / "docs"

PHASES = [  # (key, legend label) in stacking order
    ("server_ms", "Server setup"),
    ("ot_ms", "Oblivious transfer"),
    ("finish_ms", "Reconstruction + checks"),
]

THEMES = {
    # Categorical slots 1-3 of the reference data-viz palette (validated colorblind-safe as a
    # set in both modes); chrome inks per mode. `page` is GitHub's background, used for the
    # 2px gaps between stacked segments so they read as gaps.
    "light": {
        "series": ["#257de0", "#f47230", "#00b894"],
        "ink": "#191919",
        "muted": "#666666",
        "grid": "#e7e7e7",
        "axis": "#c2c2c2",
        "page": "#ffffff",
    },
    "dark": {
        "series": ["#338ced", "#e76624", "#00a888"],
        "ink": "#efefef",
        "muted": "#9c9c9c",
        "grid": "#303030",
        "axis": "#474747",
        "page": "#0d1117",
    },
}


def plot(rows, meta, theme_name):
    theme = THEMES[theme_name]
    rows = [r for r in rows if r["group"] == "modp2048"]
    labels = [f"n={r['n']}, t={r['t']}, e={r['e']}   ({r['subsets']:,} subsets)" for r in rows]

    plt.rcParams.update({"font.family": FONT, "font.size": 10.5, "text.color": theme["ink"]})
    fig, ax = plt.subplots(figsize=(9.6, 4.2), dpi=200)
    fig.patch.set_alpha(0)
    ax.set_facecolor("none")

    y = range(len(rows))
    left = [0.0] * len(rows)
    for (key, label), color in zip(PHASES, theme["series"]):
        widths = [r[key] / 1000 for r in rows]
        ax.barh(y, widths, left=left, height=0.56, color=color, edgecolor=theme["page"], linewidth=2, label=label)
        left = [a + b for a, b in zip(left, widths)]

    # Direct label: the total, at the end of each bar.
    for i, r in enumerate(rows):
        ax.text(left[i] + 0.25, i, f"{r['login_ms'] / 1000:.1f} s", va="center", ha="left", color=theme["ink"])

    ax.set_yticks(list(y), labels)
    ax.invert_yaxis()
    ax.tick_params(axis="y", length=0, colors=theme["ink"], pad=8)
    ax.tick_params(axis="x", colors=theme["muted"], length=0)
    ax.set_xlabel("seconds per login", color=theme["muted"])
    ax.set_xlim(0, max(left) * 1.1)
    ax.xaxis.grid(True, color=theme["grid"], linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "bottom"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(theme["axis"])

    # Title block left-aligned with the figure edge; legend sits on the plot's top edge.
    fig.text(0.012, 0.955, "Login time in the 2048-bit group", fontsize=13, fontweight="bold", va="top")
    fig.text(
        0.012,
        0.87,
        f"Median of {meta['repeats']} logins with one wrong bit. Reconstruction tries all C(n,t) subsets, "
        "so it dominates as n and t grow.",
        color=theme["muted"],
        fontsize=9.5,
        va="top",
    )
    legend = ax.legend(
        loc="lower left", bbox_to_anchor=(0, 1.0), ncol=3, frameon=False, handlelength=1.2, borderaxespad=0.3
    )
    for text in legend.get_texts():
        text.set_color(theme["ink"])

    fig.subplots_adjust(left=0.255, right=0.97, top=0.74, bottom=0.14)
    out = DOCS / f"benchmark-{theme_name}.png"
    fig.savefig(out, transparent=True)
    plt.close(fig)
    return out


def main() -> None:
    data = json.loads((DOCS / "benchmark.json").read_text())
    for theme in THEMES:
        print("wrote", plot(data["rows"], data["meta"], theme))


if __name__ == "__main__":
    main()
