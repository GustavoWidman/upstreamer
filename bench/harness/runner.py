"""Runs the matrix: origin per profile, then for each repetition every
scenario, every server in rotated round-robin order, one JSONL record per run.
"""

import datetime as dt
import json
import os
import platform
import socket
import subprocess
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import loadgen, upstreamer
from . import topology as t
from .procs import (
    CpuSnapshot,
    MemorySampler,
    Scope,
    breakdown,
    loadavg,
    raise_nofile,
    run_pinned,
)
from .scenarios import METRICS_SCRAPE_S, STATIC_FILE, SMALL, Feature, Scenario
from .servers import Context, Server
from .tools import tool, tools

SCHEMA = 1
LOADGEN_IDLE_MIN = 0.10
ORIGIN_IDLE_MIN = 0.20
PROXY_IDLE_MAX = 0.10
PROXY_FOREIGN_MAX = 0.10
PROXY_STEAL_MAX = 0.05
QUIET_WAIT_MAX_S = 3600
# Flags that say the host, not the server, moved the number: such runs are
# invalid and re-queued at the end of the matrix.
NOISE = frozenset({"foreign_load", "steal"})
INVALID = frozenset({"errors", "work_mismatch", "loadgen_saturated", "loadgen_failed"}) | NOISE
RATE_MISS = 0.95
READY_TIMEOUT = 45.0
# Each origin address of a balanced scenario must take at least this share of the requests.
BALANCE_SHARE_MIN = 0.2


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def git_state(path: Path) -> dict:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=path, capture_output=True, text=True, check=False
        ).stdout.strip()

    return {"rev": git("rev-parse", "HEAD") or None, "dirty": bool(git("status", "--porcelain"))}


@dataclass
class Assets:
    cert: Path
    key: Path
    cert_and_key: Path
    www: Path

    @classmethod
    def ensure(cls, root: Path) -> "Assets":
        tls = root / "tls"
        www = root / "www"
        tls.mkdir(parents=True, exist_ok=True)
        www.mkdir(parents=True, exist_ok=True)
        cert, key, both = tls / "cert.pem", tls / "key.pem", tls / "cert-and-key.pem"
        if not cert.exists():
            subprocess.run(
                [
                    tool("openssl").exe("openssl"),
                    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "3650", "-subj", "/CN=bench.test",
                    "-addext", "subjectAltName=DNS:bench.test,DNS:localhost,IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert),
                ],
                check=True,
                capture_output=True,
            )
            both.write_text(cert.read_text() + key.read_text())
        page = www / STATIC_FILE
        if not page.exists():
            head = b"<!doctype html><title>bench</title><p>"
            page.write_bytes(head + b"x" * (SMALL - len(head)))
        return cls(cert, key, both, www)


class Origin:
    def __init__(self, profile: t.Profile, log_dir: Path):
        self.profile = profile
        self.scope = Scope(
            "origin",
            [tool("origin").exe("bench-origin"), "--listen", f"{t.HOST}:{t.ORIGIN_PORT}",
             "--listen", f"{t.HOST}:{t.ORIGIN_PORT2}", "--threads", str(len(profile.origin))],
            profile.origin,
            log_dir / f"origin-{profile.name}.log",
        )
        deadline = time.monotonic() + 10
        while True:
            try:
                self.stats()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)

    def stats(self) -> dict:
        with urllib.request.urlopen(f"http://{t.HOST}:{t.ORIGIN_PORT}/__stats", timeout=5) as r:
            return json.loads(r.read())

    def stop(self) -> None:
        self.scope.stop()


class Session:
    """A results directory plus one never-overwritten JSONL file per session."""

    def __init__(self, root: Path, repo: Path, label: str):
        self.root = root.resolve()
        self.id = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
        self.dir = self.root / "sessions" / self.id
        self.dir.mkdir(parents=True)
        self.results = self.dir / "results.jsonl"
        self._out = self.results.open("x")
        self.assets = Assets.ensure(self.root)
        self.repo = repo
        self.bench_git = git_state(repo)
        self.label = label
        self.host = {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "nproc": os.cpu_count(),
            "nofile": raise_nofile(),
        }
        (self.dir / "session.json").write_text(
            json.dumps(
                {
                    "id": self.id,
                    "label": label,
                    "started": now(),
                    "bench_git": self.bench_git,
                    "host": self.host,
                    "tools": {n: tl.version for n, tl in tools().items()},
                },
                indent=2,
            )
        )

    def write(self, record: dict) -> None:
        self._out.write(json.dumps(record, sort_keys=True) + "\n")
        self._out.flush()
        os.fsync(self._out.fileno())


def wait_port_free(port: int, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while True:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((t.HOST, port))
                return
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"port {port} is still in use")
                time.sleep(0.2)


def probe(scenario: Scenario, port_override: int | None, workdir: Path) -> str | None:
    """Return None when 4 requests on the scenario's protocol and path all
    succeed with the expected body size, else a reason."""
    target = loadgen.url(scenario, port_override)
    argv = [tool("h2load").exe("h2load"), "-n", "4", "-c", "1", "-T", "5", *loadgen.h2load_flags(scenario)]
    try:
        out = subprocess.run(
            [*argv, target], capture_output=True, text=True, timeout=15, cwd=workdir
        ).stdout
    except subprocess.TimeoutExpired:
        return "probe timed out"
    if "4 succeeded" not in out or "status codes: 4 2xx" not in out:
        return "probe failed: " + " | ".join(
            line.strip() for line in out.splitlines() if line.startswith(("requests:", "status codes:"))
        )
    data = loadgen._num(r"\((\d+)\) data", out, -1)
    if data != 4 * scenario.response_bytes:
        return f"probe body size {data / 4:.0f} != {scenario.response_bytes}"
    return None


def wait_quiet(profile: t.Profile, progress=print, max_wait_s: float = QUIET_WAIT_MAX_S) -> dict:
    """Block until the host's task CPU use (everything but steal, irq and
    idle) stays under the profile's quiet_cores_max for a 2 s sample. lab is
    shared; this keeps another job's build or test from landing inside a
    measured window."""
    start = time.monotonic()
    announced = False
    while True:
        a = CpuSnapshot.take()
        time.sleep(2)
        b = CpuSnapshot.take()
        bd = breakdown(a, b, a.cpus.keys())
        busy = (bd["user"] + bd["nice"] + bd["system"]) / (b.at - a.at)
        waited = time.monotonic() - start
        if busy < profile.quiet_cores_max or waited >= max_wait_s:
            return {"busy_cores_before": busy, "waited_s": waited, "gave_up": busy >= profile.quiet_cores_max}
        if not announced:
            progress(f"host busy ({busy:.1f} cores of foreign work); waiting for quiet")
            announced = True
        time.sleep(8)


@dataclass
class RunSpec:
    server: Server
    scenario: Scenario
    profile: t.Profile
    mode: str
    rate: float | None
    rep: int
    warmup_s: int
    duration_s: int


class Runner:
    def __init__(self, session: Session):
        self.session = session
        self.origin: Origin | None = None
        self.quiet: dict | None = None

    def start_server(self, spec: RunSpec, run_dir: Path) -> Scope | None:
        server = spec.server
        if not server.launches:
            return None
        for port in (t.H1_PORT, t.TLS_PORT, t.STATIC_PORT, *t.ADMIN_PORTS):
            wait_port_free(port)
        ctx = Context(**self._ctx_args(spec, run_dir))
        server.write_config(ctx)
        return Scope(
            server.name,
            server.argv(ctx),
            spec.profile.proxy,
            run_dir / "server.log",
            cwd=run_dir,
            env=server.env(ctx),
        )

    def _ctx_args(self, spec: RunSpec, run_dir: Path) -> dict:
        a = self.session.assets
        server = spec.server
        config_name = (server.feature_template if spec.scenario.features else None) or server.template or f"{server.name}.conf"
        return dict(
            run_dir=run_dir,
            config=run_dir / config_name,
            workers=spec.profile.workers,
            cpus=t.cpulist(spec.profile.proxy),
            cert=a.cert,
            key=a.key,
            cert_and_key=a.cert_and_key,
            www=a.www,
            pkg=tool(server.tool).path if server.tool else Path("/"),
            scenario=spec.scenario,
        )

    def wait_ready(self, spec: RunSpec, scope: Scope | None, run_dir: Path) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        reason = "not probed"
        while time.monotonic() < deadline:
            if scope and not scope.alive():
                raise RuntimeError(f"{spec.server.name} exited during startup: {scope.log}")
            reason = probe(spec.scenario, spec.server.port_override, run_dir)
            if reason is None:
                return
            time.sleep(0.25)
        raise RuntimeError(f"{spec.server.name} not ready for {spec.scenario.name}: {reason}")

    def run(self, spec: RunSpec) -> dict:
        run_id = uuid.uuid4().hex[:12]
        run_dir = self.session.dir / "runs" / f"{spec.profile.name}-{spec.scenario.name}-{spec.server.name}-{spec.mode}-r{spec.rep}-{run_id}"
        run_dir.mkdir(parents=True)
        record = {
            "schema": SCHEMA,
            "run_id": run_id,
            "session": self.session.id,
            "label": self.session.label,
            "started": now(),
            "server": spec.server.name,
            "server_version": spec.server.version,
            "competitor": spec.server.competitor,
            "scenario": spec.scenario.name,
            "scenario_version": spec.scenario.version,
            "profile": spec.profile.name,
            "mode": spec.mode,
            "rate_target": spec.rate,
            "rep": spec.rep,
            "warmup_s": spec.warmup_s,
            "duration_s": spec.duration_s,
            "cpus": {
                "proxy": spec.profile.proxy,
                "origin": spec.profile.origin,
                "loadgen": spec.profile.loadgen_for(spec.scenario.client_heavy),
            },
            "bench_git": self.session.bench_git,
            "host": self.session.host,
            "loadavg_before": loadavg(),
            "quiet": self.quiet,
            "run_dir": str(run_dir),
        }
        if spec.server.name == upstreamer.NAME:
            b = upstreamer.built()
            record["upstreamer"] = {"rev": b.rev, "dirty": b.dirty, "src": str(b.src)}
        scope = None
        try:
            scope = self.start_server(spec, run_dir)
            self.wait_ready(spec, scope, run_dir)
            if spec.scenario.idle:
                record.update(self._measure_idle(spec, scope, run_dir))
            else:
                record.update(self._measure(spec, scope, run_dir))
            record["status"] = "ok"
        except Exception as e:  # one broken run must not stop an unattended matrix
            record["status"] = "failed"
            record["failure"] = f"{type(e).__name__}: {e}"
            record["valid"] = False
            record["flags"] = ["failed"]
        finally:
            if scope:
                record.setdefault("proxy", {})["mem_peak_cgroup_bytes"] = scope.memory_peak()
                scope.stop()
        record["ended"] = now()
        self.session.write(record)
        return record

    def _measure(self, spec: RunSpec, scope: Scope | None, run_dir: Path) -> dict:
        sc, prof = spec.scenario, spec.profile
        port = spec.server.port_override
        lg_cpus = prof.loadgen_for(sc.client_heavy)
        if spec.warmup_s:
            warm = loadgen.plan(sc, lg_cpus, spec.warmup_s, run_dir, "warmup", spec.rate, port)
            run_pinned(warm.argv, lg_cpus, warm.output, cwd=run_dir)
        assert self.origin
        main = loadgen.plan(sc, lg_cpus, spec.duration_s, run_dir, "measure", spec.rate, port)
        o_before = self.origin.stats()
        o_cpu0 = self.origin.scope.cpu_seconds()
        p_cpu0 = scope.cpu_seconds() if scope else 0.0
        snap0 = CpuSnapshot.take()
        scraper = Scraper(spec.server, run_dir) if Feature.METRICS in sc.features else None
        if scope:
            with MemorySampler(scope) as mem:
                if scraper:
                    scraper.start()
                fin = run_pinned(main.argv, lg_cpus, main.output, cwd=run_dir)
        else:
            mem = None
            fin = run_pinned(main.argv, lg_cpus, main.output, cwd=run_dir)
        if scraper:
            scraper.stop()
        snap1 = CpuSnapshot.take()
        p_cpu1 = scope.cpu_seconds() if scope else 0.0
        o_cpu1 = self.origin.scope.cpu_seconds()
        o_after = self.origin.stats()
        result = main.parse()
        window = snap1.at - snap0.at

        proxy_cpu = p_cpu1 - p_cpu0
        origin_cpu = o_cpu1 - o_cpu0
        roles = {"proxy": (prof.proxy, proxy_cpu), "origin": (prof.origin, origin_cpu), "loadgen": (lg_cpus, fin.cpu_seconds)}
        usage = {}
        for role, (cpus, cpu_s) in roles.items():
            b = breakdown(snap0, snap1, cpus)
            capacity = window * len(cpus)
            task = b["user"] + b["nice"] + b["system"]
            usage[role] = {
                "cpu_s": cpu_s,
                "util": cpu_s / capacity,
                # Tickless idle accounting can overshoot the window slightly.
                "idle_frac": min(1.0, (b["idle"] + b["iowait"]) / capacity),
                "softirq_frac": (b["softirq"] + b["irq"]) / capacity,
                "steal_frac": b["steal"] / capacity,
                "foreign_frac": max(0.0, task - cpu_s) / capacity,
            }
        everything = breakdown(snap0, snap1, snap0.cpus.keys())
        task_all = everything["user"] + everything["nice"] + everything["system"]
        ours = proxy_cpu + origin_cpu + fin.cpu_seconds
        origin_requests = o_after["requests"] - o_before["requests"]
        out = {
            "result": result.as_dict(),
            "loadgen_exit": fin.returncode,
            "window_s": window,
            "usage": usage,
            "system": {
                "task_cores": task_all / window,
                "softirq_cores": (everything["softirq"] + everything["irq"]) / window,
                "foreign_cores": max(0.0, task_all - ours) / window,
                "steal_cores": everything["steal"] / window,
                "loadavg_after": loadavg(),
            },
            "origin": {
                "requests": origin_requests,
                "body_bytes_in": o_after["body_bytes_in"] - o_before["body_bytes_in"],
                "body_bytes_out": o_after["body_bytes_out"] - o_before["body_bytes_out"],
                "connections": o_after["connections"] - o_before["connections"],
                "requests_by_address": [
                    a - b for a, b in zip(o_after["requests_by_listener"], o_before["requests_by_listener"])
                ],
            },
            "proxy": {
                "pss_peak_bytes": mem.pss_peak if mem else None,
                "mem_current_peak_bytes": mem.current_peak if mem else None,
            },
        }
        if scraper:
            out["metrics_scrapes"] = scraper.summary()
        out["flags"] = flags = self._flags(spec, result, usage, out, fin.returncode)
        out["valid"] = not (INVALID & set(flags))
        return out

    def _flags(self, spec: RunSpec, result: loadgen.LoadResult, usage: dict, out: dict, rc: int) -> list[str]:
        sc = spec.scenario
        flags = []
        if rc != 0:
            flags.append("loadgen_failed")
        if result.errors.total:
            flags.append("errors")
        if result.requests == 0:
            flags.append("work_mismatch")
        else:
            per = (result.body_bytes if result.body_bytes is not None else result.bytes) / result.requests
            exact = result.body_bytes is not None
            if (exact and abs(per - sc.response_bytes) > 0.01 * sc.response_bytes + 1) or (not exact and per < sc.response_bytes):
                flags.append("work_mismatch")
        origin_requests = out["origin"]["requests"]
        if sc.proxied:
            slack = sc.in_flight * 2 + 0.01 * result.requests
            if abs(origin_requests - result.requests) > slack:
                flags.append("work_mismatch")
            if sc.request_bytes and out["origin"]["body_bytes_in"] < result.requests * sc.request_bytes * 0.99:
                flags.append("work_mismatch")
        elif origin_requests > 10:
            flags.append("work_mismatch")
        if sc.balanced and origin_requests:
            if min(out["origin"]["requests_by_address"]) < BALANCE_SHARE_MIN * origin_requests:
                flags.append("work_mismatch")
        if "metrics_scrapes" in out:
            m = out["metrics_scrapes"]
            if m["failed"] or m["ok"] < spec.duration_s // METRICS_SCRAPE_S:
                flags.append("work_mismatch")
        if usage["loadgen"]["idle_frac"] < LOADGEN_IDLE_MIN and spec.mode == "closed":
            flags.append("loadgen_saturated")
        if usage["origin"]["idle_frac"] < ORIGIN_IDLE_MIN:
            flags.append("origin_saturated")
        if out["system"]["foreign_cores"] > spec.profile.foreign_cores_max:
            flags.append("foreign_load")
        if spec.server.launches:
            if spec.mode == "closed" and usage["proxy"]["idle_frac"] > PROXY_IDLE_MAX:
                flags.append("proxy_below_saturation")
            # In open loop the proxy's vCPUs are mostly idle, and other tasks
            # using that idle time do not displace the proxy.
            if spec.mode == "closed" and usage["proxy"]["foreign_frac"] > PROXY_FOREIGN_MAX:
                flags.append("foreign_load")
            if usage["proxy"]["steal_frac"] > PROXY_STEAL_MAX:
                flags.append("steal")
        if spec.rate and result.rps < RATE_MISS * spec.rate:
            flags.append("rate_missed")
        return sorted(set(flags))

    def _measure_idle(self, spec: RunSpec, scope: Scope | None, run_dir: Path) -> dict:
        sc, prof = spec.scenario, spec.profile
        assert scope and self.origin
        time.sleep(1)

        def memory() -> dict:
            return {"pss": scope.pss(), "cgroup": scope.memory_current(), "anon": scope.memory_anon()}

        base = memory()
        o_before = self.origin.stats()
        lg_cpus = prof.loadgen_for(sc.client_heavy)
        main = loadgen.plan(sc, lg_cpus, 0, run_dir, "measure", None, spec.server.port_override)
        box: dict = {}
        th = threading.Thread(target=lambda: box.update(fin=run_pinned(main.argv, lg_cpus, main.output, cwd=run_dir)))
        th.start()
        while th.is_alive() and not (main.output.exists() and "BENCH_IDLE_READY" in main.output.read_text(errors="replace")):
            time.sleep(0.1)
        time.sleep(2)
        samples = []
        for _ in range(3):
            samples.append(memory())
            time.sleep(0.5)
        connected = self.origin.stats()["requests"] - o_before["requests"]
        th.join()
        fin = box["fin"]
        result = main.parse()
        held = max(samples, key=lambda s: s["pss"])
        idle = {
            "connections_target": sc.connections,
            "connections_reached_origin": connected,
            "pss_before_bytes": base["pss"],
            "pss_bytes": held["pss"],
            "cgroup_before_bytes": base["cgroup"],
            "cgroup_bytes": held["cgroup"],
            "anon_before_bytes": base["anon"],
            "anon_bytes": held["anon"],
            "pss_per_conn_bytes": (held["pss"] - base["pss"]) / sc.connections,
            "cgroup_per_conn_bytes": (held["cgroup"] - base["cgroup"]) / sc.connections,
        }
        flags = []
        if result.requests < sc.connections or connected < sc.connections:
            flags.append("work_mismatch")
        if result.errors.total:
            flags.append("errors")
        if fin.returncode:
            flags.append("loadgen_failed")
        return {
            "result": result.as_dict(),
            "idle": idle,
            "flags": flags,
            "valid": not flags,
            "usage": {"loadgen": {"cpu_s": fin.cpu_seconds, "util": fin.cpu_seconds / (fin.wall_seconds * len(lg_cpus))}},
        }


class Scraper:
    """Scrapes the server's metrics endpoint every METRICS_SCRAPE_S seconds from the harness's
    CPUs while the load runs, as a Prometheus server would; the first scrape is immediate.
    Every response must be a 200 with a body."""

    def __init__(self, server: Server, run_dir: Path):
        self.url = f"http://{t.HOST}:{t.ADMIN_PORTS[0]}{server.metrics_path}"
        self.log = run_dir / "scrapes.log"
        self.ok = 0
        self.failed = 0
        self.bytes = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        with self.log.open("w") as log:
            while True:
                started = time.monotonic()
                try:
                    with urllib.request.urlopen(self.url, timeout=5) as r:
                        body = r.read()
                        good = r.status == 200 and bool(body)
                        self.bytes += len(body)
                        log.write(f"{now()} {r.status} {len(body)}\n")
                except OSError as e:
                    good = False
                    log.write(f"{now()} error {e}\n")
                if good:
                    self.ok += 1
                else:
                    self.failed += 1
                if self._stop.wait(max(0.0, METRICS_SCRAPE_S - (time.monotonic() - started))):
                    return

    def summary(self) -> dict:
        return {"url": self.url, "ok": self.ok, "failed": self.failed, "bytes": self.bytes}


_AFFINITY = os.sched_getaffinity(0)


def pin_harness(profile: t.Profile) -> None:
    """Pin this process (and the threads it starts later) to the profile's
    harness CPUs, so its sampling never runs on the proxy's vCPUs."""
    os.sched_setaffinity(0, profile.harness or _AFFINITY)


def rotate(items: list, k: int) -> list:
    if not items:
        return items
    k %= len(items)
    return items[k:] + items[:k]


def matrix(
    session: Session,
    profiles: list[t.Profile],
    scenarios: list[Scenario],
    servers: list[Server],
    reps: int,
    mode: str,
    warmup_s: int,
    duration_s: int,
    rates: dict | None = None,
    progress=print,
    retries: int = 2,
    quiet_wait_s: float = QUIET_WAIT_MAX_S,
) -> list[dict]:
    """Interleave servers round-robin within each scenario, rotating the order
    every repetition, so drift and warm caches favour no server. Runs the host
    disturbed (NOISE flags) or that failed are re-queued at the end of their
    profile, up to `retries` more times; every attempt stays in the JSONL."""
    runner = Runner(session)
    records = []
    by_profile: dict[str, list] = {}
    for profile in profiles:
        items = by_profile.setdefault(profile.name, [])
        for rep in range(reps):
            for sc in scenarios:
                if mode == "open" and not sc.open_loop:
                    continue
                eligible = [s for s in servers if s.runs(sc)]
                for server in rotate(eligible, rep):
                    items.append((profile, rep, sc, server))
    total = sum(len(v) for v in by_profile.values())
    done = 0
    try:
        for profile in profiles:
            if runner.origin:
                runner.origin.stop()
            pin_harness(profile)
            wait_port_free(t.ORIGIN_PORT)
            wait_port_free(t.ORIGIN_PORT2)
            runner.origin = Origin(profile, session.dir)
            queue = by_profile[profile.name]
            for attempt in range(retries + 1):
                again = []
                for item in queue:
                    _, rep, sc, server = item
                    rate = None
                    if mode == "open":
                        rate = (rates or {}).get(profile.name, {}).get(sc.name)
                        if not rate:
                            progress(f"skip {sc.name}/{profile.name}: no open-loop rate stored")
                            continue
                    runner.quiet = wait_quiet(profile, progress, quiet_wait_s)
                    rec = runner.run(RunSpec(server, sc, profile, mode, rate, rep, warmup_s, duration_s))
                    rec_retry = rec["status"] != "ok" or bool(NOISE & set(rec.get("flags", [])))
                    records.append(rec)
                    if attempt == 0:
                        done += 1
                    res = rec.get("result", {})
                    progress(
                        f"[{done}/{total}{f' retry {attempt}' if attempt else ''}] {profile.name} {sc.name} {server.name} rep{rep} {mode}: "
                        f"{rec['status']} rps={res.get('rps', 0):.0f} p99={(res.get('latency') or {}).get('p99_ms')} "
                        f"flags={','.join(rec.get('flags', []))}"
                        + (f" {rec.get('failure')}" if rec["status"] != "ok" else "")
                    )
                    if rec_retry:
                        again.append(item)
                queue = again
                if not queue:
                    break
    finally:
        if runner.origin:
            runner.origin.stop()
    return records
