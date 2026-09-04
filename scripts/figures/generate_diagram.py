"""The architecture diagram, drawn from the control registry and the benchmark.

The README describes the gateway with an ASCII block. That works in a terminal
and not much else, so this emits the same idea as an SVG with an explicit light
ground, readable wherever GitHub renders it.

Control names and stages come from the registry itself, and the corpus counts
from assets/results.json, so the picture cannot describe controls the code does
not have.

    python scripts/figures/generate_diagram.py

Output: docs/architecture.svg
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "src"))

INK = "#111827"
MUTED = "#6B7280"
FAINT = "#9CA3AF"
HAIR = "#E5E7EB"
BLUE, BLUE_BG = "#2563EB", "#EFF6FF"
GREEN, GREEN_BG = "#059669", "#ECFDF5"
AMBER, AMBER_BG = "#D97706", "#FFFBEB"
GREY_BG = "#F9FAFB"
FONT = "Segoe UI, -apple-system, Helvetica, Arial, sans-serif"

STAGE_COLOUR = {
    "discovery": (AMBER_BG, AMBER),
    "request": (BLUE_BG, BLUE),
    "response": (GREEN_BG, GREEN),
}


def controls_by_stage() -> dict[str, list[str]]:
    """Read the registry rather than restating it."""
    from mcp_policy_gateway.engine import default_controls

    out: dict[str, list[str]] = {"discovery": [], "request": [], "response": []}
    for control in default_controls():
        for stage in control.stages:
            key = getattr(stage, "value", str(stage)).lower()
            if key in out and control.name not in out[key]:
                out[key].append(control.name)
    return out


def text(x, y, s, cls="sub", anchor="start"):
    return f'  <text class="{cls}" x="{x}" y="{y}" text-anchor="{anchor}">{s}</text>\n'


def box(x, y, w, h, fill, edge, title, lines):
    s = (
        f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="{fill}" '
        f'stroke="{edge}" stroke-width="1.4"/>\n'
        f'  <text class="lbl" x="{x + w / 2}" y="{y + 25}" text-anchor="middle">'
        f"{title}</text>\n"
    )
    for i, ln in enumerate(lines):
        s += text(x + w / 2, y + 45 + i * 17, ln, "sub", "middle")
    return s


def arrow(x1, y1, x2, y2, label=None, colour=None):
    c = colour or MUTED
    head = 8.0
    dx, dy = x2 - x1, y2 - y1
    ln = max((dx * dx + dy * dy) ** 0.5, 1e-6)
    ux, uy = dx / ln, dy / ln
    ex, ey = x2 - ux * head, y2 - uy * head
    px, py = -uy, ux
    s = (
        f'  <line x1="{x1}" y1="{y1}" x2="{ex:.1f}" y2="{ey:.1f}" stroke="{c}" '
        f'stroke-width="1.7"/>\n'
        f'  <polygon points="{x2},{y2} {ex + px * 4.6:.1f},{ey + py * 4.6:.1f} '
        f'{ex - px * 4.6:.1f},{ey - py * 4.6:.1f}" fill="{c}"/>\n'
    )
    if label:
        s += text((x1 + x2) / 2, (y1 + y2) / 2 - 9, label, "cap", "middle")
    return s


def main() -> int:
    stages = controls_by_stage()
    results = json.loads((REPO / "assets" / "results.json").read_text("utf-8"))
    corpus = results["corpus"]
    gateway = results["configurations"]["gateway"]

    W, H = 1080, 716
    s = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'width="{W}" height="{H}" font-family="{FONT}">\n'
        f'  <rect width="{W}" height="{H}" fill="#FFFFFF"/>\n'
        f"  <defs><style>\n"
        f"    .h {{ fill:{INK}; font-size:19px; font-weight:600; }}\n"
        f"    .s {{ fill:{MUTED}; font-size:12.5px; }}\n"
        f"    .lbl {{ fill:{INK}; font-size:13.5px; font-weight:600; }}\n"
        f"    .sub {{ fill:{MUTED}; font-size:11px; }}\n"
        f"    .mono {{ font-family:ui-monospace,Consolas,monospace; font-size:11px; "
        f"fill:#374151; }}\n"
        f"    .cap {{ fill:{FAINT}; font-size:11.5px; }}\n"
        f"    .stage {{ fill:{INK}; font-size:12.5px; font-weight:600; }}\n"
        f"  </style></defs>\n"
    )
    s += text(30, 36, "Policy enforcement at the protocol boundary", "h")
    s += text(
        30,
        58,
        "The client speaks ordinary MCP to the gateway; the gateway speaks "
        "ordinary MCP to the real server. Both sides are unmodified.",
        "s",
    )

    s += box(30, 96, 190, 66, GREY_BG, HAIR, "MCP client", ["your agent or IDE"])
    s += arrow(224, 129, 278, 129, "MCP")
    s += box(282, 96, 216, 66, BLUE_BG, BLUE, "Policy gateway", ["nine controls"])
    s += arrow(502, 129, 556, 129, "MCP")
    s += box(560, 96, 216, 66, GREY_BG, HAIR, "Downstream server", ["source not required"])
    # The trace is written by the gateway, not by the server behind it.
    s += arrow(390, 166, 390, 196, None, FAINT)
    s += box(282, 200, 216, 56, GREY_BG, HAIR, "Trace (JSONL)", ["decision, rules, timing"])

    s += text(30, 300, "Three points where untrusted material enters", "stage")
    y = 318
    lanes = [
        ("discovery", "Tool declarations", "prose the server writes about itself"),
        ("request", "Call arguments", "built by a model, sent to the server"),
        ("response", "Tool results", "content the server did not author"),
    ]
    for stage, title, why in lanes:
        fill, edge = STAGE_COLOUR[stage]
        s += box(30, y, 250, 74, fill, edge, title, [why])
        names = stages.get(stage, [])
        s += text(300, y + 26, stage, "stage")
        s += text(300, y + 46, ", ".join(n.replace("_", " ") for n in names), "mono")
        s += text(300, y + 64, f"{len(names)} controls run here", "cap")
        y += 92

    s += f'  <line x1="30" y1="{y + 6}" x2="{W - 30}" y2="{y + 6}" stroke="{HAIR}"/>\n'
    caught = round(gateway["caught"] * corpus["attacks"])
    blocked = round(gateway["false_block"] * corpus["benign"])
    s += text(30, y + 34, "A control never decides alone", "lbl")
    for i, ln in enumerate(
        [
            "Each control reports findings. The engine combines them and the strongest "
            "action wins: allow, sanitise, hold for approval, or block.",
            f"Measured on {corpus['attacks']} attacks and {corpus['benign']} benign "
            f"near misses: {caught} attacks caught, {blocked} legitimate calls "
            f"wrongly blocked.",
        ]
    ):
        s += text(30, y + 56 + i * 19, ln, "cap")
    s += "</svg>\n"

    for chunk in s.split("<text")[1:]:
        body = chunk.split(">", 1)[1].split("</text>")[0]
        assert "\n" not in body, "newline inside a text element"

    out = REPO / "docs" / "architecture.svg"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(s, encoding="utf-8", newline="\n")
    print(f"  wrote {out.relative_to(REPO).as_posix()}")
    for stage, names in stages.items():
        print(f"    {stage:<10} {len(names)} controls: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
