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
