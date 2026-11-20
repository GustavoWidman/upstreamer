"""Summaries: per scenario, profile and mode, the median and range of every
server's valid runs, the winner, and upstreamer's margin to the best
competitor against the combined spread."""

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .runner import INVALID

CEILING = frozenset({"steal", "loadgen_saturated"})
from .scenarios import SCENARIOS, lookup
from .servers import registry

OPEN_LOOP_FRACTION = 0.5


def load(root: Path, sessions: list[str] | None = None, label: str | None = None) -> list[dict]:
    records = []
    for path in sorted((root / "sessions").glob("*/results.jsonl")):
        if sessions and path.parent.name not in sessions:
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if label and rec.get("label") != label:
                continue
            records.append(rec)
    return records


@dataclass
class Stat:
    metric: str
    higher_is_better: bool
    values: list[float]
    invalid: int
    flags: dict[str, int]
    extra: dict

    @property
    def median(self) -> float:
        return statistics.median(self.values)

    @property
    def lo(self) -> float:
        return min(self.values)

    @property
    def hi(self) -> float:
        return max(self.values)

    @property
    def spread(self) -> float:
        return self.hi - self.lo

    def as_dict(self) -> dict:
        d = {"metric": self.metric, "n": len(self.values), "invalid": self.invalid, "flags": self.flags, **self.extra}
        if self.values:
            d.update(median=self.median, min=self.lo, max=self.hi, values=self.values)
        return d


def _metric(rec: dict) -> tuple[str, bool, float | None]:
    if rec["scenario"] == "idle-tls" or rec.get("idle"):
        idle = rec.get("idle") or {}
        return "proxy_pss_bytes", False, idle.get("pss_bytes")
    res = rec.get("result") or {}
    if rec["mode"] == "open":
        return "p99_ms", False, (res.get("latency") or {}).get("p99_ms")
    return "rps", True, res.get("rps")


def _median(xs: list[float]) -> float | None:
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def summarize(records: list[dict]) -> dict:
    groups: dict[tuple, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for rec in records:
        key = (rec["profile"], rec["scenario"], rec["scenario_version"], rec["mode"])
        groups[key][rec["server"]].append(rec)
    out = []
    for (profile, scenario, version, mode), by_server in sorted(groups.items()):
        stats: dict[str, Stat] = {}
        for server, recs in sorted(by_server.items()):
            metric, higher, _ = _metric(recs[0])
            valid = [r for r in recs if r.get("valid") and _metric(r)[2] is not None]
            if mode == "open":
                valid = [r for r in valid if "rate_missed" not in r.get("flags", [])]
            # Some runs fail only because the scenario hits a ceiling of this
            # host: steal from its own load on the fastest server's vCPUs, or a
            # load generator that cannot outrun the server. Dropping them would
            # rank the wrong winner, so fall back to them and label the row; a
            # loadgen-bound median is a lower bound.
            fallback = None
            if not valid:
                ceiling = [
                    r for r in recs
                    if r.get("status") == "ok" and _metric(r)[2] is not None
                    and (set(r.get("flags", [])) & INVALID)
                    and (set(r.get("flags", [])) & INVALID) <= CEILING
                    and not (mode == "open" and "rate_missed" in r.get("flags", []))
                ]
                if ceiling:
                    valid = ceiling
                    hit = set().union(*(set(r["flags"]) & CEILING for r in ceiling))
                    fallback = "loadgen_bound" if "loadgen_saturated" in hit else "steal"
            flags: dict[str, int] = defaultdict(int)
            for r in recs:
                for f in r.get("flags", []):
                    flags[f] += 1
            res = [r.get("result") or {} for r in valid]
            usage = [r.get("usage") or {} for r in valid]
            extra = {
                "runs": len(recs),
                "rps_median": _median([x.get("rps") for x in res]),
                "bytes_per_s_median": _median([x.get("bytes_per_s") for x in res]),
                "p50_ms_median": _median([(x.get("latency") or {}).get("p50_ms") for x in res]),
                "p99_ms_median": _median([(x.get("latency") or {}).get("p99_ms") for x in res]),
                "p999_ms_median": _median([(x.get("latency") or {}).get("p999_ms") for x in res]),
                "proxy_util_median": _median([(u.get("proxy") or {}).get("util") for u in usage]),
                "loadgen_util_max": max([(u.get("loadgen") or {}).get("util") or 0 for u in usage], default=None),
                "origin_util_max": max([(u.get("origin") or {}).get("util") or 0 for u in usage], default=None),
                "proxy_cpu_us_per_req_median": _median(
                    [
                        (u.get("proxy") or {}).get("cpu_s", 0) * 1e6 / x["requests"]
                        for u, x in zip(usage, res)
                        if x.get("requests")
                    ]
                ),
                "proxy_steal_median": _median([(u.get("proxy") or {}).get("steal_frac") for u in usage]),
                "fallback": fallback,
                "versions": sorted({r.get("server_version") for r in recs}),
                "failures": sorted({r.get("failure") for r in recs if r.get("failure")}),
            }
            if metric == "proxy_pss_bytes":
                extra["pss_per_conn_bytes_median"] = _median([(r.get("idle") or {}).get("pss_per_conn_bytes") for r in valid])
            invalid = len(recs) - (0 if fallback else len(valid))
            stats[server] = Stat(metric, higher, [_metric(r)[2] for r in valid], invalid, dict(flags), extra)

        def better(a: Stat, b: Stat) -> bool:
            return a.median > b.median if a.higher_is_better else a.median < b.median

        ranked = [s for s in stats if stats[s].values]
        winner = None
        for s in ranked:
            if s == "direct":
                continue
            if winner is None or better(stats[s], stats[winner]):
                winner = s
        competitors = [s for s in ranked if s not in ("direct", "upstreamer")]
        best = None
        for s in competitors:
            if best is None or better(stats[s], stats[best]):
                best = s
        margin = None
        if "upstreamer" in ranked and best:
            u, b = stats["upstreamer"], stats[best]
            sign = 1 if u.higher_is_better else -1
            diff = sign * (u.median - b.median)
            combined = u.spread / 2 + b.spread / 2
            if (u.lo > b.hi) if u.higher_is_better else (u.hi < b.lo):
                verdict = "upstreamer better, ranges disjoint"
            elif (u.hi < b.lo) if u.higher_is_better else (u.lo > b.hi):
                verdict = "upstreamer worse, ranges disjoint"
            else:
                verdict = "no separation, ranges overlap"
            margin = {
                "best_competitor": best,
                "margin": diff,
                "margin_pct": 100 * diff / b.median if b.median else None,
                "combined_spread": combined,
                "exceeds_spread": abs(diff) > combined,
                "verdict": verdict,
            }
        out.append(
            {
                "profile": profile,
                "scenario": scenario,
                "scenario_version": version,
                "mode": mode,
                "servers": {s: st.as_dict() for s, st in stats.items()},
                "winner": winner,
                "best_competitor": best,
                "upstreamer_margin": margin,
            }
        )
    return {"groups": out, "rates": open_loop_rates(out), "not_applicable": not_applicable()}


def open_loop_rates(groups: list[dict]) -> dict:
    """Open-loop rate per profile and scenario: half the slowest competitor's
    closed-loop median throughput."""
    rates: dict[str, dict[str, float]] = defaultdict(dict)
    for g in groups:
        if g["mode"] != "closed" or g["scenario_version"] != _current_version(g["scenario"]):
            continue
        medians = [
            st["median"]
            for name, st in g["servers"].items()
            if name not in ("direct", "upstreamer") and st.get("median") and st["metric"] == "rps"
        ]
        if medians:
            rates[g["profile"]][g["scenario"]] = OPEN_LOOP_FRACTION * min(medians)
    return dict(rates)


def _current_version(name: str) -> int | None:
    sc = SCENARIOS.get(name)
    return sc.version if sc else None


def not_applicable() -> dict:
    out = {}
    for name, server in registry().items():
        reasons = {}
        for sc in SCENARIOS.values():
            reason = server.not_applicable_reason(sc)
            if reason:
                reasons[sc.name] = reason
        out[name] = reasons
    return out


def _fmt(metric: str, v: float | None) -> str:
    if v is None:
        return "-"
    if metric == "rps":
        return f"{v:,.0f}"
    if metric == "proxy_pss_bytes":
        return f"{v / 2**20:,.1f} MiB"
    return f"{v:.2f} ms"


def markdown(summary: dict) -> str:
    lines = ["# Benchmark summary", ""]
    lines.append("Median and range over valid runs. `n` counts valid runs; `bad` counts runs flagged invalid (errors, work mismatch, saturated load generator, host noise) or failed, including re-queued attempts. A server with no valid runs whose runs failed only on a host ceiling (proxy steal, or a saturated load generator) is summarized from those runs and labelled; a loadgen-bound median is a lower bound. Closed loop ranks by req/s, open loop by p99 at the fixed rate, idle-tls by proxy PSS with 10k connections open.")
    lines.append("")
    for g in summary["groups"]:
        sc = lookup(g["scenario"])
        any_stat = next(iter(g["servers"].values()))
        metric = any_stat["metric"]
        title = f"## {g['scenario']} v{g['scenario_version']} / {g['profile']} / {g['mode']} loop"
        lines += [title, "", sc.description + ".", ""]
        lines.append("| server | median | range | n | bad | p50 | p99 | p99.9 | proxy util | proxy CPU us/req | loadgen util max | flags |")
        lines.append("|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")
        order = sorted(
            g["servers"].items(),
            key=lambda kv: (kv[1].get("median") is None, -(kv[1].get("median") or 0) if kv[1]["metric"] == "rps" else (kv[1].get("median") or 0)),
        )
        for name, st in order:
            mark = " (winner)" if name == g["winner"] else ""
            if st.get("fallback") == "steal":
                mark += f" [steal-only runs, proxy steal {100 * (st.get('proxy_steal_median') or 0):.0f}%]"
            elif st.get("fallback") == "loadgen_bound":
                mark += " [load generator saturated: lower bound]"
            rng = f"{_fmt(metric, st.get('min'))} to {_fmt(metric, st.get('max'))}" if st.get("values") else "-"
            def ms(k):
                v = st.get(k)
                return f"{v:.2f}" if v is not None else "-"
            pu = st.get("proxy_util_median")
            lu = st.get("loadgen_util_max")
            cpr = st.get("proxy_cpu_us_per_req_median")
            flags = ", ".join(f"{k}x{v}" for k, v in sorted(st["flags"].items()))
            lines.append(
                f"| {name}{mark} | {_fmt(metric, st.get('median'))} | {rng} | {st['n']} | {st['invalid']} | {ms('p50_ms_median')} | {ms('p99_ms_median')} | {ms('p999_ms_median')} | "
                f"{f'{pu:.2f}' if pu is not None else '-'} | {f'{cpr:.1f}' if cpr is not None else '-'} | {f'{lu:.2f}' if lu is not None else '-'} | {flags} |"
            )
        m = g["upstreamer_margin"]
        if m:
            lines += ["", f"upstreamer vs {m['best_competitor']}: margin {_fmt(metric, m['margin'])} ({m['margin_pct']:+.1f}%), combined spread {_fmt(metric, m['combined_spread'])}; {m['verdict']}."]
        lines.append("")
    if summary["rates"]:
        lines += ["## Open-loop rates", "", "Half the slowest competitor's closed-loop median.", "", "| profile | scenario | req/s |", "|---|---|---:|"]
        for prof, by in sorted(summary["rates"].items()):
            for sc, r in sorted(by.items()):
                lines.append(f"| {prof} | {sc} | {r:,.0f} |")
        lines.append("")
    lines += ["## Not applicable", "", "| server | scenario | reason |", "|---|---|---|"]
    for server, reasons in sorted(summary["not_applicable"].items()):
        for sc, why in sorted(reasons.items()):
            lines.append(f"| {server} | {sc} | {why} |")
    return "\n".join(lines) + "\n"


def write(root: Path, summary: dict, name: str = "summary") -> tuple[Path, Path]:
    md = root / f"{name}.md"
    js = root / f"{name}.json"
    md.write_text(markdown(summary))
    js.write_text(json.dumps(summary, indent=2, sort_keys=True))
    return md, js
