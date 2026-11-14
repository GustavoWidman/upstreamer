"""The one place that knows how to build, configure and launch upstreamer.

When upstreamer gains a new config format or protocols, change only this file:
CAPABILITIES, CONFIG, argv() and build().
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import topology as t
from .scenarios import Capability as C
from .servers import Context, Server

NAME = "upstreamer"

CAPABILITIES = frozenset({C.H1})

NOT_APPLICABLE = {
    C.TLS: "this upstreamer build has no TLS listener",
    C.H2: "this upstreamer build has no TLS or HTTP/2 listener",
    C.H3: "this upstreamer build has no QUIC listener",
    C.STATIC: "this upstreamer build has no file server",
}

CONFIG = f"""\
listen = "{t.HOST}:{t.H1_PORT}"
metrics_addr = "{t.HOST}:{t.ADMIN_PORTS[0]}"

[[routes]]
match_path = "/"
lb_algorithm = "round_robin"

[[routes.pools]]
name = "origin"

[[routes.pools.origins]]
url = "http://{t.HOST}:{t.ORIGIN_PORT}"
"""


@dataclass(frozen=True)
class Build:
    binary: Path
    src: Path
    rev: str
    dirty: bool


_build: Build | None = None


def build(src: Path) -> Build:
    """Release-build upstreamer from a source tree with the pinned toolchain."""
    global _build
    src = src.resolve()
    target = src / "target"
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--bin", NAME],
        cwd=src,
        check=True,
        # A user-level cargo config may redirect the target dir or wrap rustc;
        # pin both so the binary path is known and the build is the toolchain's own.
        env={**os.environ, "CARGO_TARGET_DIR": str(target), "RUSTC_WRAPPER": "", "CARGO_BUILD_RUSTC_WRAPPER": ""},
    )
    rev = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=src, capture_output=True, text=True, check=False
    ).stdout.strip() or "unknown"
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no", "--", "src", "Cargo.toml", "Cargo.lock"],
            cwd=src,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    )
    _build = Build(target / "release" / NAME, src, rev, dirty)
    return _build


def built() -> Build:
    if _build is None:
        raise RuntimeError("upstreamer.build() must run before upstreamer is launched")
    return _build


def _argv(ctx: Context) -> list[str]:
    ctx.config.write_text(CONFIG)
    return [str(built().binary), "--config", str(ctx.config), "--log-level", "warn"]


def server() -> Server:
    return Server(
        name=NAME,
        tool=None,
        capabilities=CAPABILITIES,
        not_applicable=NOT_APPLICABLE,
        template=None,
        argv=_argv,
        competitor=False,
        version_override="source build",
        tuning=("release build with the crate's own settings", "log level warn"),
    )
