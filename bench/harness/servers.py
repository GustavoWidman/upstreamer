"""Every server the harness can run, with what it supports and how it starts.

Configs live in bench/servers/ as templates; `{{name}}` placeholders are filled
from `Context.values()`. A capability a server lacks maps to the
reason it is n/a, which the report prints.
"""

import importlib
import pkgutil
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import topology as t
from .scenarios import Capability as C
from .tools import tool

TEMPLATES = Path(__file__).resolve().parent.parent / "servers"


@dataclass(frozen=True)
class Context:
    """Everything a config template or a command line may refer to."""

    run_dir: Path
    config: Path
    workers: int
    cpus: str
    cert: Path
    key: Path
    cert_and_key: Path
    www: Path
    pkg: Path

    def values(self) -> dict[str, str]:
        return {
            "host": t.HOST,
            "origin_host": t.HOST,
            "origin_port": str(t.ORIGIN_PORT),
            "origin": f"{t.HOST}:{t.ORIGIN_PORT}",
            "h1_port": str(t.H1_PORT),
            "tls_port": str(t.TLS_PORT),
            "static_port": str(t.STATIC_PORT),
            "admin_port": str(t.ADMIN_PORTS[0]),
            "admin_port2": str(t.ADMIN_PORTS[1]),
            "workers": str(self.workers),
            "cpus": self.cpus,
            "cert": str(self.cert),
            "key": str(self.key),
            "cert_and_key": str(self.cert_and_key),
            "www": str(self.www),
            "run_dir": str(self.run_dir),
            "config": str(self.config),
            "pkg": str(self.pkg),
        }


def render(text: str, values: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        if m.group(1) not in values:
            raise KeyError(f"template placeholder {{{{{m.group(1)}}}}} has no value")
        return values[m.group(1)]

    return re.sub(r"\{\{(\w+)\}\}", sub, text)


@dataclass(frozen=True)
class Server:
    name: str
    tool: str | None
    capabilities: frozenset[C]
    not_applicable: dict[C, str]
    template: str | None
    argv: Callable[[Context], list[str]]
    env: Callable[[Context], dict[str, str]] = lambda ctx: {}
    tuning: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    port_override: int | None = None
    competitor: bool = True
    launches: bool = True
    version_override: str | None = None
    meta: dict = field(default_factory=dict)

    @property
    def version(self) -> str:
        if self.version_override:
            return self.version_override
        return tool(self.tool).version if self.tool else "-"

    def supports(self, capability: C) -> bool:
        return capability in self.capabilities

    def write_config(self, ctx: Context) -> None:
        if self.template:
            text = (TEMPLATES / self.template).read_text()
            ctx.config.write_text(render(text, ctx.values()))


def exe(name: str, binary: str | None = None) -> str:
    return tool(name).exe(binary)


ALL = frozenset(C)
NO_FILES = "proxy only; has no static file server"

DIRECT = Server(
    name="direct",
    tool="origin",
    capabilities=frozenset({C.H1}),
    not_applicable={c: "the origin speaks cleartext HTTP/1.1 only" for c in ALL - {C.H1}},
    template=None,
    argv=lambda ctx: [],
    port_override=t.ORIGIN_PORT,
    competitor=False,
    launches=False,
)

def competitors() -> list[Server]:
    from . import competitors as pkg

    found = []
    for mod in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda m: m.name):
        found.append(importlib.import_module(f"{pkg.__name__}.{mod.name}").SERVER)
    return found


def registry() -> dict[str, Server]:
    from . import upstreamer

    servers = {s.name: s for s in competitors()}
    servers[upstreamer.NAME] = upstreamer.server()
    servers[DIRECT.name] = DIRECT
    return servers
