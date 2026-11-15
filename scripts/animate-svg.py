#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 sigmacatch contributors
"""Make Archify SVG exports animated.

Archify's viewer animates the diagrams at runtime, but its SVG export is a
frozen snapshot: the keyframes are inlined, yet no rule applies them. This
script appends a small stylesheet that animates every edge carrying
``data-animate="edge"`` (the exported marker), so the diagrams keep moving
when embedded in the documentation.

Usage: scripts/animate-svg.py docs/media/*.svg
"""

import sys

STYLE = """<style id="sigmacatch-motion">
@media (prefers-reduced-motion: no-preference) {
  [data-animate="edge"] {
    stroke-dasharray: 6 6;
    animation: sigmacatch-flow 1.2s linear infinite;
  }
  @keyframes sigmacatch-flow {
    to { stroke-dashoffset: -24; }
  }
}
</style>
"""


def animate(path: str) -> bool:
    with open(path, encoding="utf-8") as handle:
        svg = handle.read()
    if 'id="sigmacatch-motion"' in svg:
        return False
    if 'data-animate="edge"' not in svg:
        return False
    end = svg.rfind("</svg>")
    if end < 0:
        return False
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(svg[:end] + STYLE + svg[end:])
    return True


def main() -> int:
    changed = 0
    for path in sys.argv[1:]:
        if animate(path):
            print(f"animated: {path}")
            changed += 1
    return 0 if changed or len(sys.argv) > 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
