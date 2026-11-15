"""The one place that knows how to build, configure and launch upstreamer.

When upstreamer gains a new config format or protocols, change only this file:
CAPABILITIES, config(), _argv() and build().
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import topology as t
from .servers import ALL, Context, Server

NAME = "upstreamer"

CAPABILITIES = ALL


def _site(name: str, port: int, routes: list[dict], ctx: Context, http3: bool | None = None) -> dict:
    """One virtual host on one address. TLS sites carry `localhost`, the SNI every client sends,
    so the certificate is chosen by name; `*` takes the Host headers that name the IP."""
    site = {
        "name": name,
        "hosts": ["*"],
        "listen": [f"{t.HOST}:{port}"],
        "routes": routes,
    }
    if http3 is not None:
        site["hosts"] = ["localhost", "*"]
        site["tls"] = {"cert": str(ctx.cert), "key": str(ctx.key), "redirectHttp": False, "http3": http3}
    return site


def config(ctx: Context) -> dict:
    proxy = [{"proxy": f"http://{t.HOST}:{t.ORIGIN_PORT}"}]
    return {
        "version": 1,
        "workers": ctx.workers,
        "sites": [
            _site("h1", t.H1_PORT, proxy, ctx),
            _site("tls", t.TLS_PORT, proxy, ctx, http3=True),
            _site("static", t.STATIC_PORT, [{"files": {"root": str(ctx.www)}}], ctx, http3=False),
        ],
    }


@dataclass(frozen=True)
class Build:
    binary: Path
    src: Path
    rev: str
    dirty: bool


_build: Build | None = None


def build(src: Path) -> Build:
    """Build upstreamer from a source tree with `nix build <tree>#default`: the flake's own
    derivation, so the tree's pinned toolchain (rust-toolchain.toml through fenix), its release
    profile, and the same binary the NixOS module deploys. Uncommitted edits to tracked files
    are part of the build and set `dirty`. The out-link `result-bench` in the tree is a garbage
    collector root, so an automatic collection cannot delete the binary while it is measured."""
    global _build
    src = src.resolve()
    out = subprocess.run(
        ["nix", "build", f"{src}#default", "--out-link", str(src / "result-bench"), "--print-out-paths"],
        cwd=src,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip().splitlines()[-1]
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
    _build = Build(Path(out) / "bin" / NAME, src, rev, dirty)
    return _build


def built() -> Build:
    if _build is None:
        raise RuntimeError("upstreamer.build() must run before upstreamer is launched")
    return _build


def _argv(ctx: Context) -> list[str]:
    ctx.config.write_text(json.dumps(config(ctx), indent=2))
    return [str(built().binary), "run", "--config", str(ctx.config)]


def server() -> Server:
    return Server(
        name=NAME,
        tool=None,
        capabilities=CAPABILITIES,
        not_applicable={},
        template=None,
        argv=_argv,
        competitor=False,
        version_override="source build",
        tuning=(
            "nix build of the tree's flake package: pinned toolchain, release profile (fat LTO, one codegen unit, panic abort)",
            "workers = profile vCPUs, one pinned thread per vCPU of the proxy's affinity mask, SO_REUSEPORT listener per thread",
            "no access log; logs warnings and errors to stderr",
            "three sites on their own addresses: cleartext proxy, TLS proxy (HTTP/1.1, HTTP/2 and HTTP/3 with Alt-Svc), TLS static files",
            "tls with the given cert for SNI localhost; TLS 1.3 and 1.2 with rustls defaults; one session ticket per handshake; no HTTP->HTTPS redirect",
            "defaults kept: keep-alive 75 s, header timeout 10 s, 128 streams per HTTP/2 or HTTP/3 connection, pooled origin connections idle 2 m",
            "no response compression; static files from the static dir, no precompressed sidecars",
        ),
    )
