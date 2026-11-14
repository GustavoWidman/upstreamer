"""bench: run, summarize, profile and spot-check the proxy benchmark matrix.

  bench run      full interleaved matrix (closed, open or both loops)
  bench report   summary.md / summary.json from the stored JSONL
  bench refresh  re-measure competitors and rewrite their stored medians
  bench quick    upstreamer only, compared against stored competitor medians
  bench profile  perf flamegraph of one server under one scenario (not a measurement)
  bench serve    start origin + one server, probe each scenario it supports
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import report, upstreamer
from . import topology as t
from .loadgen import plan as loadgen_plan
from .procs import raise_nofile, run_pinned
from .runner import Origin, Runner, RunSpec, Session, matrix, probe, wait_port_free
from .scenarios import SCENARIOS, lookup
from .servers import registry
from .tools import tool


def split(value: str) -> list[str]:
    return [v for v in value.split(",") if v]


def pick_servers(names: str) -> list:
    reg = registry()
    if names == "all":
        return [s for s in reg.values()]
    if names == "competitors":
        return [s for s in reg.values() if s.competitor]
    unknown = [n for n in split(names) if n not in reg]
    if unknown:
        raise SystemExit(f"unknown servers {unknown}; known: {', '.join(reg)}")
    return [reg[n] for n in split(names)]


def pick_scenarios(names: str) -> list:
    return list(SCENARIOS.values()) if names == "all" else [lookup(n) for n in split(names)]


def pick_profiles(names: str) -> list:
    return [t.profile(n) for n in names.split(",") if n]


def prepare_upstreamer(servers: list, src: Path) -> None:
    if any(s.name == upstreamer.NAME for s in servers):
        b = upstreamer.build(src)
        print(f"upstreamer {b.rev[:12]}{' (dirty)' if b.dirty else ''} built at {b.binary}", flush=True)


def write_report(root: Path, label: str | None) -> dict:
    summary = report.summarize(report.load(root, label=label))
    name = f"summary-{label}" if label else "summary"
    md, js = report.write(root, summary, name)
    print(f"wrote {md} and {js}")
    return summary


def cmd_run(a: argparse.Namespace) -> None:
    servers = pick_servers(a.servers)
    prepare_upstreamer(servers, a.upstreamer_src)
    root = a.out
    modes = ["closed", "open"] if a.mode == "both" else [a.mode]
    for mode in modes:
        rates = None
        if mode == "open":
            rates = report.summarize(report.load(root, label=a.label))["rates"]
            if a.rates:
                rates = json.loads(a.rates.read_text())
        session = Session(root, a.repo, a.label)
        print(f"session {session.id}: {session.results}", flush=True)
        matrix(
            session,
            pick_profiles(a.profiles),
            pick_scenarios(a.scenarios),
            servers,
            a.reps,
            mode,
            a.warmup,
            a.duration,
            rates,
            progress=lambda m: print(m, flush=True),
        )
    write_report(root, a.label)


def cmd_report(a: argparse.Namespace) -> None:
    write_report(a.out, a.label)


def cmd_refresh(a: argparse.Namespace) -> None:
    a.servers = "competitors"
    cmd_run(a)


def cmd_quick(a: argparse.Namespace) -> None:
    servers = pick_servers(upstreamer.NAME)
    prepare_upstreamer(servers, a.upstreamer_src)
    against = json.loads(a.against.read_text())
    session = Session(a.out, a.repo, "quick")
    print(f"session {session.id}: {session.results}", flush=True)
    records = matrix(
        session, pick_profiles(a.profiles), pick_scenarios(a.scenarios), servers, a.reps,
        a.mode, a.warmup, a.duration, against.get("rates"), progress=lambda m: print(m, flush=True),
    )
    mine = report.summarize(records)["groups"]
    stored = {(g["profile"], g["scenario"], g["scenario_version"], g["mode"]): g for g in against["groups"]}
    print()
    print("| profile | scenario | mode | upstreamer median (range) | best competitor median (range) | margin | verdict |")
    print("|---|---|---|---|---|---:|---|")
    for g in mine:
        key = (g["profile"], g["scenario"], g["scenario_version"], g["mode"])
        u = g["servers"].get(upstreamer.NAME, {})
        ref = stored.get(key)
        if not ref or not ref.get("best_competitor") or not u.get("values"):
            print(f"| {key[0]} | {key[1]} | {key[3]} | {u.get('median')} | no stored competitor medians | - | - |")
            continue
        b = ref["servers"][ref["best_competitor"]]
        higher = u["metric"] == "rps"
        diff = (u["median"] - b["median"]) * (1 if higher else -1)
        combined = (u["max"] - u["min"]) / 2 + (b["max"] - b["min"]) / 2
        if (u["min"] > b["max"]) if higher else (u["max"] < b["min"]):
            verdict = "better, ranges disjoint"
        elif (u["max"] < b["min"]) if higher else (u["min"] > b["max"]):
            verdict = "worse, ranges disjoint"
        else:
            verdict = "overlap"
        print(
            f"| {key[0]} | {key[1]} | {key[3]} | {u['median']:,.2f} ({u['min']:,.2f} to {u['max']:,.2f}) | "
            f"{ref['best_competitor']} {b['median']:,.2f} ({b['min']:,.2f} to {b['max']:,.2f}) | "
            f"{100 * diff / b['median']:+.1f}% (spread {combined:,.2f}) | {verdict} |"
        )


def cmd_serve(a: argparse.Namespace) -> None:
    server = pick_servers(a.server)[0]
    prepare_upstreamer([server], a.upstreamer_src)
    profile = pick_profiles(a.profile)[0]
    session = Session(a.out, a.repo, "serve")
    runner = Runner(session)
    wait_port_free(t.ORIGIN_PORT)
    runner.origin = Origin(profile, session.dir)
    run_dir = session.dir / "runs" / f"serve-{server.name}"
    run_dir.mkdir(parents=True)
    scenarios = [s for s in SCENARIOS.values() if server.supports(s.requires)]
    scope = None
    failed = False
    try:
        spec = RunSpec(server, scenarios[0], profile, "closed", None, 0, 0, 0)
        scope = runner.start_server(spec, run_dir)
        runner.wait_ready(spec, scope, run_dir)
        for sc in SCENARIOS.values():
            if not server.supports(sc.requires):
                print(f"n/a   {sc.name}: {server.not_applicable.get(sc.requires, 'not supported')}")
                continue
            reason = probe(sc, server.port_override, run_dir)
            failed |= reason is not None
            print(f"{'ok  ' if reason is None else 'FAIL'}  {sc.name}{'' if reason is None else ': ' + reason}")
        print(f"config and logs: {run_dir}")
        if a.hold:
            print("holding; Ctrl-C to stop", flush=True)
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        if scope:
            scope.stop()
        runner.origin.stop()
    sys.exit(1 if failed else 0)


def cmd_profile(a: argparse.Namespace) -> None:
    server = pick_servers(a.server)[0]
    prepare_upstreamer([server], a.upstreamer_src)
    profile = pick_profiles(a.profile)[0]
    sc = lookup(a.scenario)
    session = Session(a.out, a.repo, "profile")
    runner = Runner(session)
    wait_port_free(t.ORIGIN_PORT)
    runner.origin = Origin(profile, session.dir)
    out = a.out / "profiles" / f"{session.id}-{profile.name}-{sc.name}-{server.name}"
    out.mkdir(parents=True)
    scope = None
    try:
        spec = RunSpec(server, sc, profile, "closed", None, 0, a.warmup, a.duration)
        scope = runner.start_server(spec, out)
        runner.wait_ready(spec, scope, out)
        warm = loadgen_plan(sc, profile.loadgen, a.warmup, out, "warmup", None, server.port_override)
        run_pinned(warm.argv, profile.loadgen, warm.output, cwd=out)
        main = loadgen_plan(sc, profile.loadgen, a.duration + 2, out, "load", None, server.port_override)
        pids = scope.pids()
        loader = subprocess.Popen(["taskset", "-c", t.cpulist(profile.loadgen), *main.argv], stdout=open(main.output, "wb"), stderr=subprocess.STDOUT)
        time.sleep(1)
        perf = tool("perf").exe("perf")
        subprocess.run(
            [perf, "record", "-e", "cpu-clock", "-F", str(a.frequency), "--call-graph", a.call_graph,
             "-p", ",".join(map(str, pids)), "-o", str(out / "perf.data"), "--", "sleep", str(a.duration)],
            check=True, stdout=subprocess.DEVNULL, stderr=open(out / "perf.log", "wb"),
        )
        loader.wait()
    finally:
        if scope:
            scope.stop()
        runner.origin.stop()
    folded = out / "stacks.folded"
    with open(out / "perf.script", "wb") as f:
        subprocess.run([perf, "script", "-i", str(out / "perf.data")], stdout=f, stderr=subprocess.DEVNULL, check=True)
    inferno = tool("inferno")
    with open(folded, "wb") as f:
        subprocess.run([inferno.exe("inferno-collapse-perf"), str(out / "perf.script")], stdout=f, check=True)
    with open(out / "flamegraph.svg", "wb") as f:
        subprocess.run([inferno.exe("inferno-flamegraph"), "--title", f"{server.name} {sc.name} {profile.name}", str(folded)], stdout=f, check=True)
    (out / "perf.script").unlink()
    print(main.parse().as_dict()["rps"], "req/s while profiled (not a measurement)")
    print(f"wrote {out / 'flamegraph.svg'} and {folded}")


def main() -> None:
    raise_nofile()
    p = argparse.ArgumentParser(prog="bench", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=Path(os.environ.get("BENCH_OUT", "bench-results")), help="results directory (default $BENCH_OUT or ./bench-results)")
    p.add_argument("--repo", type=Path, default=Path.cwd(), help="checkout whose git rev is recorded as the harness rev")
    p.add_argument("--upstreamer-src", type=Path, default=Path.cwd(), help="upstreamer source tree to build")
    sub = p.add_subparsers(dest="cmd", required=True)

    def matrix_args(sp, servers="all", label="adhoc"):
        sp.add_argument("--profiles", default="fleet,wide")
        sp.add_argument("--scenarios", default="all")
        sp.add_argument("--servers", default=servers, help="'all', 'competitors' or a comma list")
        sp.add_argument("--reps", type=int, default=5)
        sp.add_argument("--mode", choices=["closed", "open", "both"], default="closed")
        sp.add_argument("--warmup", type=int, default=3, help="seconds of warm-up load before each measured window")
        sp.add_argument("--duration", type=int, default=10, help="seconds per measured window")
        sp.add_argument("--label", default=label, help="tag stored on every record; report filters by it")
        sp.add_argument("--rates", type=Path, help="JSON {profile: {scenario: req/s}} for open loop")

    sp = sub.add_parser("run", help="run the interleaved matrix")
    matrix_args(sp)
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("refresh", help="re-measure competitors and rewrite their medians")
    matrix_args(sp, servers="competitors", label="baseline")
    sp.set_defaults(func=cmd_refresh)

    sp = sub.add_parser("report", help="summarize stored results")
    sp.add_argument("--label", default=None)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("quick", help="upstreamer only, against stored competitor medians")
    sp.add_argument("--profiles", default="fleet")
    sp.add_argument("--scenarios", default="h1")
    sp.add_argument("--reps", type=int, default=5)
    sp.add_argument("--mode", choices=["closed", "open"], default="closed")
    sp.add_argument("--warmup", type=int, default=3)
    sp.add_argument("--duration", type=int, default=10)
    sp.add_argument("--against", type=Path, required=True, help="summary JSON holding competitor medians")
    sp.set_defaults(func=cmd_quick)

    sp = sub.add_parser("profile", help="perf flamegraph of one server under load")
    sp.add_argument("--server", required=True)
    sp.add_argument("--scenario", default="h1")
    sp.add_argument("--profile", default="fleet")
    sp.add_argument("--warmup", type=int, default=3)
    sp.add_argument("--duration", type=int, default=10)
    sp.add_argument("--frequency", type=int, default=499)
    sp.add_argument("--call-graph", default="dwarf,16384")
    sp.set_defaults(func=cmd_profile)

    sp = sub.add_parser("serve", help="start origin and one server, probe its scenarios")
    sp.add_argument("--server", required=True)
    sp.add_argument("--profile", default="fleet")
    sp.add_argument("--hold", action="store_true", help="keep both running until Ctrl-C")
    sp.set_defaults(func=cmd_serve)

    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    a.func(a)


if __name__ == "__main__":
    main()
