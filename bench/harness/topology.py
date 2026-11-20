"""CPU layout per profile and the fixed ports every server listens on.

On the 16-vCPU bench VM, CPUs 0 and 1 are left to the harness, sshd and the
host's own services. The origin, the proxy and the load generator each get
disjoint CPU sets so none of them steals cycles from another. The layouts leave
vCPUs 11/12 to 15 idle on purpose: the bench VM's 16 vCPUs share a
power-limited 8-core mobile CPU, and past about 10 busy vCPUs hypervisor steal
climbs and total throughput falls.

A 2-vCPU host has no such room: `pair` gives the proxy vCPU 1 alone and puts
the origin, the load generator and the harness itself on vCPU 0, so that
vCPU's idle fraction says whether the client side limited the run.
"""

import os
from dataclasses import dataclass

HOST = "127.0.0.1"
# Shifts every port, so two harness instances can probe configs side by side.
# Never measure while another instance runs: they would share CPUs.
_OFFSET = int(os.environ.get("BENCH_PORT_OFFSET", "0"))
ORIGIN_PORT = 18080 + _OFFSET
# The origin's second address, for the scenarios that balance over two origins.
ORIGIN_PORT2 = 18081 + _OFFSET
H1_PORT = 19080 + _OFFSET
TLS_PORT = 19443 + _OFFSET
STATIC_PORT = 19444 + _OFFSET
ADMIN_PORTS = (19900 + _OFFSET, 19901 + _OFFSET, 19902 + _OFFSET)


def cpulist(cpus: tuple[int, ...]) -> str:
    return ",".join(map(str, cpus))


@dataclass(frozen=True)
class Profile:
    name: str
    proxy: tuple[int, ...]
    origin: tuple[int, ...]
    loadgen: tuple[int, ...]
    description: str
    # Added to the load generator for client-heavy scenarios (full TLS
    # handshakes cost the client about as much as the server).
    spare: tuple[int, ...] = ()
    # CPUs the harness process pins itself to; empty leaves it unpinned.
    harness: tuple[int, ...] = ()
    # Task CPU, in cores, other processes may use: before a run starts (quiet
    # gate) and during its measured window (else the run is flagged
    # foreign_load and re-queued).
    quiet_cores_max: float = 1.0
    foreign_cores_max: float = 1.5

    @property
    def workers(self) -> int:
        return len(self.proxy)

    def loadgen_for(self, client_heavy: bool) -> tuple[int, ...]:
        return self.loadgen + self.spare if client_heavy else self.loadgen


PROFILES = {
    p.name: p
    for p in (
        Profile(
            "fleet",
            proxy=(2, 3),
            origin=(4, 5, 6),
            loadgen=(7, 8, 9, 10),
            description="proxy on 2 vCPUs, like the 2-core production hosts",
            spare=(11, 12),
        ),
        Profile(
            "wide",
            proxy=(2, 3, 4),
            origin=(5, 6, 7),
            loadgen=(8, 9, 10, 11),
            description="proxy on 3 vCPUs, the most this VM gives before hypervisor steal reaches the proxy",
            spare=(12, 13, 14),
        ),
        Profile(
            "pair",
            proxy=(1,),
            origin=(0,),
            loadgen=(0,),
            description="2-vCPU host: proxy alone on vCPU 1; origin, load generator and harness share vCPU 0",
            harness=(0,),
            quiet_cores_max=0.2,
            foreign_cores_max=0.2,
        ),
        Profile(
            "single",
            proxy=(2,),
            origin=(4, 5, 6),
            loadgen=(7, 8, 9, 10),
            description="proxy on 1 vCPU; used by the sensitivity check only",
            spare=(11, 12),
        ),
    )
}


def _cpus(spec: str) -> tuple[int, ...]:
    out: list[int] = []
    for part in spec.split("+"):
        lo, _, hi = part.partition("-")
        out += range(int(lo), int(hi or lo) + 1)
    return tuple(out)


def profile(name: str) -> Profile:
    """A named profile, or an ad-hoc layout written as
    `custom:p=2-3:o=4-7:l=8-15` (proxy, origin, load generator CPUs; join
    ranges with `+`). Ad-hoc layouts exist for harness checks, not baselines."""
    if name in PROFILES:
        return PROFILES[name]
    if not name.startswith("custom:"):
        raise SystemExit(f"unknown profile {name!r}; known: {', '.join(PROFILES)} or custom:p=..:o=..:l=..")
    roles = dict(kv.split("=") for kv in name.split(":")[1:])
    return Profile(name, _cpus(roles["p"]), _cpus(roles["o"]), _cpus(roles["l"]), "ad-hoc layout")
