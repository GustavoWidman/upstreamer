"""Store paths and versions of every pinned tool, read from the Nix manifest."""

import json
import os
from dataclasses import dataclass
from functools import cache
from pathlib import Path


@dataclass(frozen=True)
class Tool:
    name: str
    path: Path
    bin: Path
    version: str

    def exe(self, binary: str | None = None) -> str:
        return str(self.bin / (binary or self.name))


@cache
def tools() -> dict[str, Tool]:
    manifest = os.environ.get("BENCH_TOOLS")
    if not manifest:
        raise SystemExit("BENCH_TOOLS is not set: run the harness through `nix run .#bench`")
    data = json.loads(Path(manifest).read_text())
    return {
        name: Tool(name, Path(v["path"]), Path(v["bin"]), v["version"])
        for name, v in data.items()
    }


def tool(name: str) -> Tool:
    return tools()[name]
