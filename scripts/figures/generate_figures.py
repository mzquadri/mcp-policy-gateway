"""Charts for the gateway benchmark, drawn from assets/results.json.

The benchmark writes per case outcomes for all three configurations, so every
number here is read rather than typed. Four figures, each answering one question:

    does it work, and at what cost   the catch rate against the false block rate
    where does it work               coverage by attack class
    what does the work               contribution per control
    where does it fail               the four cases nothing handles

Timing is deliberately absent. The median decision cost is machine dependent, so
putting it on a chart would imply a precision the benchmark does not have.

    python scripts/figures/generate_figures.py

Output: docs/figures/
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import portfolio_style as ps  # noqa: E402

OUT = REPO / "docs" / "figures"
RESULTS = REPO / "assets" / "results.json"

CONFIGS = [
    ("baseline", "No gateway", ps.FAINT),
    ("keyword", "Keyword filter", ps.AMBER),
    ("gateway", "Policy gateway", ps.BLUE),
]


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}.png")
    plt.close(fig)
    print(f"  wrote {name}.png")


def load():
    d = json.loads(RESULTS.read_text(encoding="utf-8"))
    n_attack = d["corpus"]["attacks"]
    n_benign = d["corpus"]["benign"]
    return d, n_attack, n_benign


def fig_tradeoff(d, n_attack, n_benign):
    """The only question that matters: what does it catch, and what does it break."""
    fig = plt.figure(figsize=(12.6, 8.0))
    ax = fig.add_axes([0.085, 0.175, 0.60, 0.585])

    for key, label, colour in CONFIGS:
        c = d["configurations"][key]
        x, y = 100 * c["false_block"], 100 * c["caught"]
        ax.scatter([x], [y], s=340, color=colour, zorder=4, edgecolors=ps.PAPER, linewidths=2.2)
        caught = round(c["caught"] * n_attack)
        blocked = round(c["false_block"] * n_benign)
        ax.annotate(
            f"{label}\n{caught} of {n_attack} attacks, {blocked} of {n_benign} benign blocked",
            (x, y),
            textcoords="offset points",
            xytext=(16, -6 if key == "keyword" else 12),
            fontsize=10.8,
            color=ps.INK,
            linespacing=1.5,
        )

    ax.set_xlim(-3, 48)
    ax.set_ylim(-5, 103)
    ps.clean(ax, grid_axis="y")
    ax.set_xlabel("legitimate calls wrongly blocked (%)", fontsize=11)
    ax.set_ylabel("attacks caught (%)", fontsize=11)

    # The corner every control is aiming for, drawn so the reader sees the target.
    ax.axhspan(75, 100, xmin=0, xmax=0.28, color=ps.GREEN_SOFT, alpha=0.20, zorder=0)
    ps.note(
        ax, 1.5, 99, "catches most attacks,\nbreaks few calls", color=ps.GREEN, size=10.6, va="top"
    )

    ps.title_block(
        fig,
        "What each option costs you",
        "Up is safety, right is friction. A control that lands to the right gets "
        "switched off by the team using it,\nwhichever way its catch rate looks.",
        y=0.962,
        size=22,
    )
    ps.footnote(
        fig,
        [
            f"Deterministic benchmark over {n_attack + n_benign} cases: {n_attack} "
            f"attacks across ten classes and {n_benign} benign near misses written to "
            f"look like attacks. No model calls, no network.",
            "The keyword filter is the honest comparison. It is what a team actually "
            "reaches for, and it refuses two in five legitimate calls to catch a third "
            "of the attacks.",
            "Source: assets/results.json, produced by evaluation/benchmark.py.",
        ],
        y=0.098,
    )
    save(fig, "01_tradeoff")


def fig_by_class(d, n_attack, n_benign):
    """Coverage per attack class, with the count behind each bar."""
    outcomes = d["configurations"]["gateway"]["outcomes"]
    total = Counter()
    caught = Counter()
    for o in outcomes:
        if o["label"] != "attack":
            continue
        cls = o["attack_class"]
        total[cls] += 1
        caught[cls] += 1 if o["ok"] else 0

    order = sorted(total, key=lambda c: (caught[c] / total[c], total[c]))
    fig = plt.figure(figsize=(12.6, 8.2))
    ax = fig.add_axes([0.275, 0.185, 0.635, 0.565])

    ypos = np.arange(len(order))
    for cls, yy in zip(order, ypos, strict=True):
        rate = caught[cls] / total[cls]
        colour = ps.GREEN if rate == 1 else (ps.AMBER if rate >= 0.5 else ps.RED)
        ax.barh(yy, rate * 100, color=colour, height=0.62, zorder=3)
        ax.text(
            -1.5, yy, cls.replace("_", " "), ha="right", va="center", fontsize=11.2, color=ps.INK
        )
        ax.text(
            rate * 100 + 1.5,
            yy,
            f"{caught[cls]} of {total[cls]}",
            va="center",
            fontsize=9.8,
            color=ps.MUTED,
        )
    ax.set_yticks([])
    ax.set_xlim(0, 118)
    ps.clean(ax, left=False, grid_axis="x")
    ax.set_xlabel("attacks caught (%)", fontsize=11)

    ps.title_block(
        fig,
        "Nine of ten attack classes are fully covered",
        "Every attack class in the corpus, worst first. The counts matter: most "
        "classes hold two or three cases, so a\nsingle miss moves a bar a long way.",
        y=0.962,
        size=22,
    )
    ps.footnote(
        fig,
        [
            "Indirect prompt injection is the one class that is not fully covered, and "
            "it is also the largest. That is the honest shape of the problem: the "
            "deterministic controls handle structural attacks, and the",
            "one judgement based control handles text, imperfectly.",
            "Source: assets/results.json, gateway configuration.",
        ],
        y=0.092,
    )
    save(fig, "02_by_attack_class")


def fig_controls(d, n_attack, n_benign):
    """Which control does the work, and where the false positives come from.

    Read from assets/control-table.json rather than recomputed. The benchmark
    counts every rule a control fires, not one per case, so a control that raises
    three findings on one attack counts three times. Recomputing it here with a
    different rule would put a figure at odds with the repository's own table.
    """
    rows = json.loads((REPO / "assets" / "control-table.json").read_text("utf-8"))
    rows = sorted(rows, key=lambda r: -r["attacks_caught"])

    fig = plt.figure(figsize=(12.6, 8.2))
    ax = fig.add_axes([0.265, 0.185, 0.615, 0.545])

    ypos = np.arange(len(rows))[::-1]
    widest = max(r["attacks_caught"] + r["benign_touched"] for r in rows)
    for r, yy in zip(rows, ypos, strict=True):
        a, b = r["attacks_caught"], r["benign_touched"]
        ax.barh(yy, a, color=ps.BLUE, height=0.58, zorder=3)
        if b:
            ax.barh(yy, b, left=a, color=ps.RED, height=0.58, zorder=3)
            ax.text(
                a + b + 0.3,
                yy,
                f"{a} attack findings, {b} benign",
                va="center",
                fontsize=9.8,
                color=ps.RED,
            )
        else:
            ax.text(a + 0.3, yy, str(a), va="center", fontsize=9.8, color=ps.MUTED)
        ax.text(
            -0.4,
            yy,
            r["control"].replace("_", " "),
            ha="right",
            va="center",
            fontsize=11.2,
            color=ps.INK,
        )
    ax.set_yticks([])
    ax.set_xlim(0, widest + 8)
    ps.clean(ax, left=False, grid_axis="x")
    ax.set_xlabel("findings raised", fontsize=11)

    ps.label_at(ax, 0.02, 1.055, "attacks caught", ps.BLUE, transform=ax.transAxes, size=11)
    ps.label_at(ax, 0.24, 1.055, "benign calls touched", ps.RED, transform=ax.transAxes, size=11)

    ps.title_block(
        fig,
        "One control makes every judgement call",
        "Eight controls answer structural questions and never fire on a legitimate "
        "call. The ninth reads text, and\nevery false positive in the system comes "
        "from it.",
        y=0.962,
        size=22,
    )
    ps.footnote(
        fig,
        [
            "Counts are findings, not cases: a control that raises three findings on "
            "one attack appears three times, which is how the benchmark attributes "
            "credit and why the column sums exceed 26.",
            "That split is the design argument. Path traversal, egress and schema "
            "conformance have answers that are true or false, so they can block "
            "outright. Whether a sentence is an instruction aimed at a",
            "model is a judgement, so it sits in one place where its cost can be "
            "measured. Source: assets/control-table.json.",
        ],
        y=0.088,
    )
    save(fig, "03_controls")


def fig_failures(d, n_attack, n_benign):
    """The four cases nothing handles, stated plainly."""
    outcomes = d["configurations"]["gateway"]["outcomes"]
    bad = [o for o in outcomes if not o["ok"]]

    why = {
        "inject-006": (
            "Base64 of an override instruction",
            "Matching runs on raw text. Decoding every base64-looking "
            "span would flag legitimate attachments.",
        ),
        "secret-004": (
            "A bare 64 hex character credential",
            "Catching it means flagging every SHA-256 digest in every "
            "document. The control keys on prefixes and assignment "
            "shape instead.",
        ),
        "fp-known-001": (
            'A runbook saying "ignore the previous instructions"',
            "Genuine operator prose with the exact shape of an attack. No signal separates them.",
        ),
        "fp-known-002": (
            'Onboarding text asking to "show your system prompt"',
            "Same problem. Internal documentation discusses prompts now.",
        ),
    }

    fig = plt.figure(figsize=(12.6, 7.6))
    ax = fig.add_axes([0, 0, 1, 1])
    ps.bare(ax)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    y = 0.680
    for o in sorted(bad, key=lambda o: o["case_id"]):
        cid = o["case_id"]
        headline, reason = why.get(cid, ("", ""))
        miss = "attack allowed" if o["label"] == "attack" else "benign blocked"
        colour = ps.RED if o["label"] == "attack" else ps.AMBER
        ax.add_patch(
            plt.Rectangle(
                (0.055, y - 0.088), 0.892, 0.104, facecolor=ps.WASH, edgecolor=ps.HAIR, lw=1.0
            )
        )
        ax.text(
            0.072,
            y - 0.012,
            cid,
            fontsize=11.6,
            color=ps.INK,
            family="monospace",
            va="center",
            fontweight="600",
        )
        ax.text(0.196, y - 0.012, headline, fontsize=11.4, color=ps.INK, va="center")
        ax.text(0.072, y - 0.052, reason, fontsize=10.0, color=ps.MUTED, va="center")
        ax.text(
            0.930,
            y - 0.012,
            miss,
            fontsize=10.4,
            color=colour,
            va="center",
            ha="right",
            fontweight="600",
        )
        y -= 0.126

    ps.title_block(
        fig,
        "Four cases out of 44 are not handled",
        "All four were written before the controls were, and none has been quietly "
        "dropped from the corpus. Two are\nattacks that get through; two are "
        "legitimate calls that get blocked.",
        y=0.962,
        size=22,
    )
    ps.footnote(
        fig,
        [
            "The two false positives are the cost of the injection control, and the "
            "reason it is the only control allowed to be uncertain. Both are real "
            "operator prose that has the exact shape of an attack.",
            "The two misses are deliberate open gaps rather than oversights: closing "
            "either one flags a large class of legitimate content.",
            "Full write-up in docs/learning/06_failures.md. Source: assets/results.json.",
        ],
        y=0.108,
    )
    save(fig, "04_failures")


def main() -> int:
    ps.apply()
    d, n_attack, n_benign = load()
    print(f"corpus: {n_attack} attacks, {n_benign} benign, commit {d['generated_from_commit']}\n")
    fig_tradeoff(d, n_attack, n_benign)
    fig_by_class(d, n_attack, n_benign)
    fig_controls(d, n_attack, n_benign)
    fig_failures(d, n_attack, n_benign)
    print(f"\nfigures written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
