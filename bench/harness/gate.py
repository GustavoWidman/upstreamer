"""Instructions per request: user-space instructions the proxy retires per request, for two or
more upstreamer binaries under the harness's topology and configs, interleaved A/B/B/A.

    python3 -m harness.gate --bin base=/nix/store/...-a/bin/upstreamer \\
        --bin head=/nix/store/...-b/bin/upstreamer --scenarios h1,h1-tls,h2-tls,static-h2 \\
        --out bench-results --repo .

Instructions stay within about 0.1% from run to run where req/s needs disjoint ranges, so this
sees a regression of a few nanoseconds per request that req/s cannot.

Per run: start the binary in its proxy scope, wait until it answers, warm up, then count the
proxy's instructions with `perf stat -p` over a window of `--duration` seconds of load.
- A proxied scenario reads the origin's request counter around the window: the load generator
  runs for duration + 2 s, and the window opens one second in.
- A static scenario never reaches the origin, so perf wraps the load generator itself and the
  requests are the load generator's own count; the window then includes connection setup, a
  few dozen handshakes against millions of requests.
Instructions per request = user instructions / requests in the window. Runs are not records of
the matrix: they go to `gate.jsonl` in the session directory.
"""

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path

from . import topology as t
from . import upstreamer
from .loadgen import plan as loadgen_plan
from .procs import raise_nofile, run_pinned
from .runner import Origin, Runner, RunSpec, Session, pin_harness, wait_port_free, wait_quiet
from .scenarios import lookup
from .servers import registry
from .tools import tool

EVENTS = "instructions:u,cycles:u,instructions:k"


def perf_counts(path: Path) -> dict:
    counts = {}
    for line in path.read_text().splitlines():
        fields = line.split(",")
        if len(fields) > 2 and fields[0].strip().isdigit():
            counts[fields[2]] = int(fields[0])
    return counts


def one(runner: Runner, server, sc, profile, label: str, binary: str, rep: int, a, perf: str) -> dict:
    upstreamer._build = upstreamer.Build(Path(binary), Path(binary), label, False)
    run_dir = runner.session.dir / "runs" / f"{profile.name}-{sc.name}-{label}-r{rep}"
    run_dir.mkdir(parents=True)
    spec = RunSpec(server, sc, profile, "closed", None, rep, a.warmup, a.duration)
    scope = runner.start_server(spec, run_dir)
    counts_file = run_dir / "perf.csv"
    cpus = profile.loadgen_for(sc.client_heavy)
    try:
        runner.wait_ready(spec, scope, run_dir)
        warm = loadgen_plan(sc, cpus, a.warmup, run_dir, "warmup")
        run_pinned(warm.argv, cpus, warm.output, cwd=run_dir)
        pids = ",".join(map(str, scope.pids()))
        stat = [perf, "stat", "-x", ",", "-o", str(counts_file), "-e", EVENTS, "-p", pids, "--"]
        cpu_before = scope.cpu_seconds()
        if sc.proxied:
            load = loadgen_plan(sc, cpus, a.duration + 2, run_dir, "load")
            with open(load.output, "wb") as out:
                loader = subprocess.Popen(
                    ["taskset", "-c", t.cpulist(cpus), *load.argv], stdout=out, stderr=subprocess.STDOUT, cwd=run_dir
                )
            time.sleep(1)
            before = runner.origin.stats()["requests"]
            cpu_before = scope.cpu_seconds()
            subprocess.run([*stat, "sleep", str(a.duration)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            requests = runner.origin.stats()["requests"] - before
            cpu_after = scope.cpu_seconds()
            loader.wait()
            result = load.parse().as_dict()
        else:
            load = loadgen_plan(sc, cpus, a.duration, run_dir, "load")
            with open(load.output, "wb") as out:
                subprocess.run(
                    [*stat, "taskset", "-c", t.cpulist(cpus), *load.argv], check=True, stdout=out,
                    stderr=subprocess.STDOUT, cwd=run_dir,
                )
            cpu_after = scope.cpu_seconds()
            result = load.parse().as_dict()
            requests = result["requests"]
    finally:
        scope.stop()
    counts = perf_counts(counts_file)
    return {
        "label": label,
        "scenario": sc.name,
        "profile": profile.name,
        "rep": rep,
        "requests": requests,
        "instructions_u": counts.get("instructions:u"),
        "cycles_u": counts.get("cycles:u"),
        "instructions_k": counts.get("instructions:k"),
        "insn_per_req": counts.get("instructions:u", 0) / max(requests, 1),
        "kinsn_per_req": counts.get("instructions:k", 0) / max(requests, 1),
        "cpu_us_per_req": (cpu_after - cpu_before) * 1e6 / max(requests, 1),
        "rps": result.get("rps"),
        "errors": result.get("errors"),
    }


def summarize(rows: list[dict], scenarios: list[str], labels: list[str]) -> None:
    base = labels[0]
    for sc_name in scenarios:
        medians = {}
        for label in labels:
            mine = [r for r in rows if r["scenario"] == sc_name and r["label"] == label]
            if not mine:
                continue
            ipr = sorted(r["insn_per_req"] for r in mine)
            rps = sorted(r["rps"] for r in mine)
            cpu = sorted(r["cpu_us_per_req"] for r in mine)
            errors = sum(1 for r in mine if r["errors"] and r["errors"].get("total"))
            medians[label] = statistics.median(ipr)
            delta = f"{100 * (medians[label] / medians[base] - 1):+.2f}%" if label != base and base in medians else ""
            print(
                f"{sc_name:10} {label:8} insn/req median {medians[label]:9.1f} range {ipr[0]:.1f}-{ipr[-1]:.1f} {delta:>8}  "
                f"req/s median {statistics.median(rps):9.0f} range {rps[0]:.0f}-{rps[-1]:.0f}  "
                f"cpu us/req {statistics.median(cpu):.2f}  runs with errors {errors}  n={len(mine)}"
            )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bin", action="append", required=True, help="label=path, at least two; the first is the base")
    p.add_argument("--scenarios", default="h1,h1-tls,h2-tls,static-h2")
    p.add_argument("--profile", default="fleet")
    p.add_argument("--reps", type=int, default=6)
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--duration", type=int, default=10)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--summarize", type=Path, help="print the summary of an existing gate.jsonl and exit")
    a = p.parse_args()
    bins = [tuple(b.split("=", 1)) for b in a.bin]
    labels = [label for label, _ in bins]
    scenarios = a.scenarios.split(",")
    if a.summarize:
        summarize([json.loads(line) for line in a.summarize.read_text().splitlines()], scenarios, labels)
        return
    raise_nofile()
    profile = t.profile(a.profile)
    session = Session(a.out, a.repo, "offpath-gate")
    print(f"session {session.dir}", flush=True)
    runner = Runner(session)
    pin_harness(profile)
    wait_port_free(t.ORIGIN_PORT)
    runner.origin = Origin(profile, session.dir)
    server = registry()[upstreamer.NAME]
    perf = tool("perf").exe("perf")
    results = session.dir / "gate.jsonl"
    try:
        for rep in range(a.reps):
            order = bins if rep % 2 == 0 else bins[::-1]
            for sc_name in scenarios:
                sc = lookup(sc_name)
                for label, binary in order:
                    wait_quiet(profile, print, 600)
                    r = one(runner, server, sc, profile, label, binary, rep, a, perf)
                    with open(results, "a") as f:
                        f.write(json.dumps(r) + "\n")
                    print(json.dumps(r), flush=True)
    finally:
        runner.origin.stop()
    summarize([json.loads(line) for line in results.read_text().splitlines()], scenarios, labels)
    print(f"results: {results}")


if __name__ == "__main__":
    main()
