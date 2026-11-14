"""Load generator adapters. Each turns a scenario into a command line and parses
that tool's output into one LoadResult shape.

HTTP/1.1 runs on wrk (closed loop) and wrk2 (open loop, latency corrected for
coordinated omission); HTTP/2 and HTTP/3 run on h2load, which has no
percentile output, so its per-request log feeds the percentiles.
"""

import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .scenarios import Endpoint, Protocol, Scenario
from .tools import tool
from .topology import H1_PORT, HOST, STATIC_PORT, TLS_PORT

IDLE_DELAY_MS = 3_600_000


def url(scenario: Scenario, port_override: int | None = None) -> str:
    if scenario.endpoint is Endpoint.H1:
        return f"http://{HOST}:{port_override or H1_PORT}{scenario.path}"
    port = STATIC_PORT if scenario.endpoint is Endpoint.STATIC else TLS_PORT
    return f"https://{HOST}:{port_override or port}{scenario.path}"


@dataclass
class Latency:
    p50_ms: float | None = None
    p99_ms: float | None = None
    p999_ms: float | None = None
    max_ms: float | None = None
    mean_ms: float | None = None


@dataclass
class Errors:
    connect: int = 0
    read: int = 0
    write: int = 0
    timeout: int = 0
    non_2xx: int = 0
    stream: int = 0

    @property
    def total(self) -> int:
        return self.connect + self.read + self.write + self.timeout + self.non_2xx + self.stream


@dataclass
class LoadResult:
    tool: str
    version: str
    argv: list[str]
    requests: int
    duration_s: float
    bytes: int
    body_bytes: int | None
    latency: Latency
    errors: Errors
    notes: list[str] = field(default_factory=list)

    @property
    def rps(self) -> float:
        return self.requests / self.duration_s if self.duration_s else 0.0

    def as_dict(self) -> dict:
        d = asdict(self)
        d["rps"] = self.rps
        d["bytes_per_s"] = self.bytes / self.duration_s if self.duration_s else 0.0
        d["errors"]["total"] = self.errors.total
        return d


@dataclass(frozen=True)
class Plan:
    """One load generator invocation: what to run and how to read its output."""

    tool: str
    argv: list[str]
    output: Path
    log: Path | None

    def parse(self) -> LoadResult:
        text = self.output.read_text(errors="replace")
        if self.tool in ("wrk", "wrk2"):
            return _parse_wrk(self, text)
        return _parse_h2load(self, text)


def _wrk_script(scenario: Scenario, path: Path) -> Path:
    lines = [f'wrk.method = "{scenario.method}"']
    if scenario.request_bytes:
        lines.append(f'wrk.body = string.rep("x", {scenario.request_bytes})')
        lines.append('wrk.headers["Content-Type"] = "application/octet-stream"')
    if scenario.close_per_request:
        lines.append('wrk.headers["Connection"] = "close"')
    if scenario.idle:
        lines.append(f"function delay() return {IDLE_DELAY_MS} end")
    lines.append(
        """
done = function(summary, latency, requests)
  local e = summary.errors
  io.write(string.format(
    "BENCH_RESULT requests=%d duration_us=%d bytes=%d connect=%d read=%d write=%d status=%d timeout=%d p50=%d p99=%d p999=%d max=%d mean=%.3f\\n",
    summary.requests, summary.duration, summary.bytes,
    e.connect, e.read, e.write, e.status, e.timeout,
    latency:percentile(50), latency:percentile(99), latency:percentile(99.9),
    latency.max, latency.mean))
end
"""
    )
    path.write_text("\n".join(lines))
    return path


def plan(
    scenario: Scenario,
    cpus: tuple[int, ...],
    duration_s: int,
    workdir: Path,
    tag: str,
    rate: float | None = None,
    port_override: int | None = None,
) -> Plan:
    """Build the load generator command for one window of `duration_s`.

    `rate` (requests per second, total) switches to open loop.
    """
    target = url(scenario, port_override)
    threads = max(1, min(len(cpus), scenario.connections))
    output = workdir / f"{tag}.out"
    if scenario.protocol is Protocol.H1:
        name = "wrk2" if rate else "wrk"
        script = _wrk_script(scenario, workdir / f"{tag}.lua")
        argv = [
            tool(name).exe(name),
            "-t",
            str(threads),
            "-c",
            str(scenario.connections),
            "-d",
            f"{duration_s}s",
            "--timeout",
            "30s" if scenario.idle else "10s",
            "-s",
            str(script),
        ]
        if rate:
            argv += ["-R", str(max(1, round(rate)))]
        return Plan(name, [*argv, target], output, None)

    if scenario.request_bytes or scenario.close_per_request or scenario.idle:
        raise ValueError(f"h2load adapter does not implement scenario {scenario.name}")
    log = workdir / f"{tag}.reqlog"
    argv = [
        tool("h2load").exe("h2load"),
        "-t",
        str(threads),
        "-c",
        str(scenario.connections),
        "-m",
        str(scenario.streams),
        "-D",
        str(duration_s),
        f"--log-file={log}",
    ]
    if scenario.protocol is Protocol.H3:
        argv.append("--alpn-list=h3")
    if rate:
        argv.append(f"--rps={rate / scenario.connections:.3f}")
    return Plan("h2load", [*argv, target], output, log)


def _parse_wrk(p: Plan, text: str) -> LoadResult:
    m = re.search(r"BENCH_RESULT (.*)", text)
    if not m:
        raise RuntimeError(f"{p.tool} printed no result:\n{text[-2000:]}")
    v = {k: float(x) for k, x in (kv.split("=") for kv in m.group(1).split())}
    notes = []
    if p.tool == "wrk2":
        notes.append("latency corrected for coordinated omission by wrk2")
    return LoadResult(
        tool=p.tool,
        version=tool(p.tool).version,
        argv=p.argv,
        requests=int(v["requests"]),
        duration_s=v["duration_us"] / 1e6,
        bytes=int(v["bytes"]),
        body_bytes=None,
        latency=Latency(
            p50_ms=v["p50"] / 1e3,
            p99_ms=v["p99"] / 1e3,
            p999_ms=v["p999"] / 1e3,
            max_ms=v["max"] / 1e3,
            mean_ms=v["mean"] / 1e3,
        ),
        # wrk counts status >= 400 as status errors; 3xx would pass, so the
        # runner also checks bytes per response and the origin's request count.
        errors=Errors(
            connect=int(v["connect"]),
            read=int(v["read"]),
            write=int(v["write"]),
            timeout=int(v["timeout"]),
            non_2xx=int(v["status"]),
        ),
        notes=notes,
    )


def _num(pattern: str, text: str, default: float | None = None) -> float:
    m = re.search(pattern, text)
    if not m:
        if default is not None:
            return default
        raise RuntimeError(f"h2load output lacks /{pattern}/:\n{text[-2000:]}")
    return float(m.group(1))


def _percentile(sorted_values: list[int], q: float) -> float:
    if not sorted_values:
        return float("nan")
    i = max(0, math.ceil(q * len(sorted_values)) - 1)
    return float(sorted_values[i])


def _log_latency(log: Path) -> tuple[Latency, int]:
    durations: list[int] = []
    non_2xx = 0
    with log.open("rb") as f:
        for line in f:
            parts = line.split(b"\t")
            if len(parts) < 3:
                continue
            status = int(parts[1])
            if not 200 <= status < 300:
                non_2xx += 1
            durations.append(int(parts[2]))
    durations.sort()
    if not durations:
        return Latency(), non_2xx
    return (
        Latency(
            p50_ms=_percentile(durations, 0.50) / 1e3,
            p99_ms=_percentile(durations, 0.99) / 1e3,
            p999_ms=_percentile(durations, 0.999) / 1e3,
            max_ms=durations[-1] / 1e3,
            mean_ms=sum(durations) / len(durations) / 1e3,
        ),
        non_2xx,
    )


def _parse_h2load(p: Plan, text: str) -> LoadResult:
    total = int(_num(r"requests: (\d+) total", text))
    done = int(_num(r"(\d+) done", text))
    errored = int(_num(r"(\d+) errored", text))
    timeout = int(_num(r"(\d+) timeout", text))
    s3 = int(_num(r"(\d+) 3xx", text))
    s4 = int(_num(r"(\d+) 4xx", text))
    s5 = int(_num(r"(\d+) 5xx", text))
    s2 = int(_num(r"status codes: (\d+) 2xx", text))
    duration = _num(r"finished in ([\d.]+)s", text)
    traffic = int(_num(r"traffic: .*?\((\d+)\) total", text))
    data = int(_num(r"\((\d+)\) data", text))
    latency, log_non_2xx = (Latency(), 0)
    notes = []
    if p.log and p.log.exists():
        latency, log_non_2xx = _log_latency(p.log)
        p.log.unlink()
        if "--rps" in " ".join(p.argv):
            notes.append("h2load does not correct latency for coordinated omission")
    connect_failed = 0
    m = re.search(r"(\d+) connections? failed", text)
    if m:
        connect_failed = int(m.group(1))
    return LoadResult(
        tool="h2load",
        version=tool("h2load").version,
        argv=p.argv,
        requests=s2,
        duration_s=duration,
        bytes=traffic,
        body_bytes=data,
        latency=latency,
        errors=Errors(
            connect=connect_failed,
            timeout=timeout,
            non_2xx=max(s3 + s4 + s5, log_non_2xx),
            stream=errored,
        ),
        notes=notes + [f"h2load done={done} of total={total}"],
    )
