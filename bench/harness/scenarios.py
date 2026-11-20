"""Named, versioned scenario definitions.

Bump a scenario's version whenever anything that changes its numbers changes
(sizes, concurrency, protocol, load generator flags). The report never mixes
versions.
"""

from dataclasses import dataclass
from enum import StrEnum


class Capability(StrEnum):
    """What a server must support to run a scenario."""

    H1 = "h1"  # HTTP/1.1 cleartext reverse proxy
    TLS = "tls"  # HTTP/1.1 over TLS 1.3 reverse proxy
    H2 = "h2"  # HTTP/2 over TLS (ALPN) reverse proxy
    H3 = "h3"  # HTTP/3 over QUIC reverse proxy
    STATIC = "static"  # file server over TLS + HTTP/2


class Feature(StrEnum):
    """A proxy feature a scenario turns on. A server runs the scenario only when it has an
    equivalent of every feature in it; otherwise the cell is n/a with the server's reason."""

    LB_ROUND_ROBIN = "lb-round-robin"  # two origin addresses, taken in turn
    LB_LEAST = "lb-least"  # two origin addresses, fewest requests in flight
    LB_HASH = "lb-hash"  # two origin addresses, consistent hash of the client key header
    HEALTH = "health"  # active health probes of every origin address
    LIMIT_CLIENT = "limit-client"  # a rate limit with one bucket per client key, never rejecting
    LIMIT_CONST = "limit-const"  # a rate limit with one bucket for every request, never rejecting
    METRICS = "metrics"  # request metrics collected and scraped during the run
    TRUSTED = "trusted"  # the client address taken from X-Forwarded-For of a trusted peer


LB = frozenset({Feature.LB_ROUND_ROBIN, Feature.LB_LEAST, Feature.LB_HASH})

# The header a client key travels in, and how many distinct keys the load generator cycles
# through. wrk sends a different key on each request; h2load sends a fixed header, so an HTTP/2
# scenario has one key for the whole run.
CLIENT_HEADER = "X-Client"
CLIENT_KEYS = 1024
# Per-key and whole-step rates far above anything the host can drive (about 200k req/s), so no
# request is refused and the limiter's bookkeeping is what the scenario measures. 1M/s is the
# highest rate upstreamer accepts.
LIMIT_CLIENT_RATE = 1_000_000
LIMIT_CONST_RATE = 1_000_000
METRICS_PATH = "/metrics"
METRICS_SCRAPE_S = 5
HEALTH_PATH = "/bytes/2"
HEALTH_INTERVAL_S = 10


def client_key(header: str, k: int) -> str:
    """The k-th client key: an address in 10.0.0.0/22 for X-Forwarded-For, else `c<k>`."""
    if header == "X-Forwarded-For":
        return f"10.0.{k // 256}.{k % 256}"
    return f"c{k}"


class Endpoint(StrEnum):
    H1 = "h1"  # cleartext listener, proxies to the origin
    TLS = "tls"  # TLS listener (TCP h1/h2, UDP h3), proxies to the origin
    STATIC = "static"  # TLS listener serving files from the static root


class Protocol(StrEnum):
    H1 = "h1"
    H2 = "h2"
    H3 = "h3"


SMALL = 1024
LARGE = 1 << 20
STATIC_FILE = "small.html"


@dataclass(frozen=True)
class Scenario:
    name: str
    version: int
    description: str
    endpoint: Endpoint
    protocol: Protocol
    path: str
    response_bytes: int
    connections: int
    streams: int = 1
    method: str = "GET"
    request_bytes: int = 0
    close_per_request: bool = False
    idle: bool = False
    client_heavy: bool = False
    # Overrides the protocol's default load generator (wrk for HTTP/1.1,
    # h2load for HTTP/2 and HTTP/3).
    loadgen: str | None = None
    features: frozenset[Feature] = frozenset()
    # The request header that carries the client key (CLIENT_HEADER, or X-Forwarded-For for
    # a scenario behind a trusted proxy); None sends none.
    key_header: str | None = None

    @property
    def balanced(self) -> bool:
        return bool(self.features & LB)

    @property
    def proxied(self) -> bool:
        return self.endpoint is not Endpoint.STATIC

    @property
    def in_flight(self) -> int:
        return self.connections * self.streams

    @property
    def requires(self) -> Capability:
        if self.endpoint is Endpoint.STATIC:
            return Capability.STATIC
        if self.endpoint is Endpoint.H1:
            return Capability.H1
        return {
            Protocol.H1: Capability.TLS,
            Protocol.H2: Capability.H2,
            Protocol.H3: Capability.H3,
        }[self.protocol]

    @property
    def open_loop(self) -> bool:
        return not self.idle


SCENARIOS = {
    s.name: s
    for s in (
        Scenario(
            "h1",
            1,
            "HTTP/1.1 cleartext, keep-alive, 1 KiB response",
            Endpoint.H1,
            Protocol.H1,
            f"/bytes/{SMALL}",
            SMALL,
            connections=256,
        ),
        Scenario(
            "h1-tls",
            1,
            "HTTP/1.1 over TLS 1.3, keep-alive, 1 KiB response",
            Endpoint.TLS,
            Protocol.H1,
            f"/bytes/{SMALL}",
            SMALL,
            connections=256,
        ),
        Scenario(
            "h2-tls",
            1,
            "HTTP/2 over TLS 1.3, 32 connections x 8 streams, 1 KiB response",
            Endpoint.TLS,
            Protocol.H2,
            f"/bytes/{SMALL}",
            SMALL,
            connections=32,
            streams=8,
        ),
        Scenario(
            "h3",
            1,
            "HTTP/3 over QUIC, 32 connections x 8 streams, 1 KiB response",
            Endpoint.TLS,
            Protocol.H3,
            f"/bytes/{SMALL}",
            SMALL,
            connections=32,
            streams=8,
        ),
        Scenario(
            "tls-handshake",
            2,
            "HTTP/1.1 over TLS 1.3, full handshake per request (new connection each time)",
            Endpoint.TLS,
            Protocol.H1,
            f"/bytes/{SMALL}",
            SMALL,
            connections=64,
            close_per_request=True,
            client_heavy=True,
            # wrk's OpenSSL 3 client spends about 2.2 ms of CPU per handshake,
            # six times oha's rustls client, and saturated before any server.
            loadgen="oha",
        ),
        Scenario(
            "static-h2",
            1,
            "1 KiB static file over TLS 1.3 + HTTP/2, 32 connections x 8 streams",
            Endpoint.STATIC,
            Protocol.H2,
            f"/{STATIC_FILE}",
            SMALL,
            connections=32,
            streams=8,
        ),
        Scenario(
            "large-response",
            1,
            "HTTP/1.1 over TLS 1.3, keep-alive, 1 MiB response",
            Endpoint.TLS,
            Protocol.H1,
            f"/bytes/{LARGE}",
            LARGE,
            connections=32,
        ),
        Scenario(
            "large-upload",
            1,
            "HTTP/1.1 over TLS 1.3, keep-alive, 1 MiB POST body, 2-byte response",
            Endpoint.TLS,
            Protocol.H1,
            "/bytes/2",
            2,
            connections=32,
            method="POST",
            request_bytes=LARGE,
        ),
        Scenario(
            "idle-tls",
            1,
            "10k TLS keep-alive connections, one request each, then idle; proxy memory",
            Endpoint.TLS,
            Protocol.H1,
            "/bytes/2",
            2,
            connections=10_000,
            idle=True,
        ),
    )
}



def _h1_feature(name: str, description: str, features: set[Feature], key_header: str | None = None) -> Scenario:
    """The `h1` scenario with features on: its cost is read against plain `h1`."""
    return Scenario(
        name,
        1,
        description,
        Endpoint.H1,
        Protocol.H1,
        f"/bytes/{SMALL}",
        SMALL,
        connections=256,
        features=frozenset(features),
        key_header=key_header,
    )


ALL_FEATURES = {Feature.LB_ROUND_ROBIN, Feature.HEALTH, Feature.LIMIT_CLIENT, Feature.METRICS, Feature.TRUSTED}

FEATURE_SCENARIOS = (
    _h1_feature("h1-lb2", "h1, round robin over two origin addresses", {Feature.LB_ROUND_ROBIN}),
    _h1_feature("h1-lb2-least", "h1, fewest requests in flight over two origin addresses", {Feature.LB_LEAST}),
    _h1_feature(
        "h1-lb2-hash",
        f"h1, consistent hash of the {CLIENT_HEADER} header ({CLIENT_KEYS} values) over two origin addresses",
        {Feature.LB_HASH},
        CLIENT_HEADER,
    ),
    _h1_feature(
        "h1-limit",
        f"h1, rate limit keyed on the {CLIENT_HEADER} header ({CLIENT_KEYS} values), never rejecting",
        {Feature.LIMIT_CLIENT},
        CLIENT_HEADER,
    ),
    _h1_feature("h1-limit-const", "h1, rate limit with one bucket for every request, never rejecting", {Feature.LIMIT_CONST}),
    _h1_feature("h1-metrics", f"h1, request metrics on, scraped every {METRICS_SCRAPE_S} s", {Feature.METRICS}),
    _h1_feature(
        "h1-all",
        "h1, round robin over two health-checked origin addresses, per-client rate limit on the "
        f"address a trusted peer forwards in X-Forwarded-For ({CLIENT_KEYS} values), metrics scraped",
        ALL_FEATURES,
        "X-Forwarded-For",
    ),
    Scenario(
        "h2-tls-all",
        1,
        "h2-tls, round robin over two health-checked origin addresses, per-client rate limit on the "
        "address a trusted peer forwards in X-Forwarded-For (one value), metrics scraped",
        Endpoint.TLS,
        Protocol.H2,
        f"/bytes/{SMALL}",
        SMALL,
        connections=32,
        streams=8,
        features=frozenset(ALL_FEATURES),
        key_header="X-Forwarded-For",
    ),
)
SCENARIOS |= {s.name: s for s in FEATURE_SCENARIOS}

# Scenarios that exist only to prove the harness, never part of the matrix.
CHECKS = {
    s.name: s
    for s in (
        Scenario(
            "h1-small-direct",
            1,
            "HTTP/1.1 cleartext, 2-byte response (origin and load generator ceiling)",
            Endpoint.H1,
            Protocol.H1,
            "/bytes/2",
            2,
            connections=256,
        ),
    )
}


def lookup(name: str) -> Scenario:
    if name in SCENARIOS:
        return SCENARIOS[name]
    if name in CHECKS:
        return CHECKS[name]
    raise SystemExit(f"unknown scenario {name!r}; known: {', '.join([*SCENARIOS, *CHECKS])}")
