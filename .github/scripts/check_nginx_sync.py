"""The Helm chart carries copies of the nginx configuration. Fail if they drift from the originals.

  frontend/nginx.conf       == deploy/helm/mcp-gateway/files/nginx.conf, except the marked upstream block
  deploy/mtls/agent-mtls.conf == deploy/helm/mcp-gateway/files/agent-mtls.conf

Standard library only. Run from the repository root.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHART = Path("deploy/helm/mcp-gateway/files")
UPSTREAM = re.compile(r"^# >>> upstream.*?^# <<< upstream\n", re.MULTILINE | re.DOTALL)


def normalise(text: str) -> str:
    text = UPSTREAM.sub("", text.replace("\r\n", "\n"))
    return "\n".join(line for line in text.split("\n") if not line.startswith("# Helm chart copy"))


def main() -> None:
    problems = []
    pairs = [(Path("frontend/nginx.conf"), CHART / "nginx.conf", True),
             (Path("deploy/mtls/agent-mtls.conf"), CHART / "agent-mtls.conf", False)]
    for original, copy, marked in pairs:
        a, b = original.read_text(encoding="utf-8"), copy.read_text(encoding="utf-8")
        if marked and not (UPSTREAM.search(a) and UPSTREAM.search(b)):
            problems.append(f"{original} or {copy}: upstream markers missing")
        if normalise(a) != normalise(b):
            problems.append(f"{copy} differs from {original}; apply the same change to both")
    for p in problems:
        print(f"::error::{p}")
    if problems:
        sys.exit(1)
    print("chart nginx configuration in sync")


if __name__ == "__main__":
    main()
