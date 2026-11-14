import tempfile
from pathlib import Path

from ..scenarios import Capability as C
from ..servers import NO_FILES, Context, Server, exe


def _argv(ctx: Context) -> list[str]:
    # The command socket is a unix socket: run_dir paths exceed SUN_LEN (108 bytes).
    sock = Path(tempfile.mkdtemp(prefix="sozu-")) / "sozu.sock"
    ctx.config.write_text(f'command_socket = "{sock}"\n' + ctx.config.read_text())
    return [exe("sozu"), "start", "--config", str(ctx.config)]


SERVER = Server(
    name="sozu",
    tool="sozu",
    capabilities=frozenset({C.H1}),
    not_applicable={
        C.TLS: "sozu aborts TLS handshakes that carry no SNI (no fallback certificate); the load generators send none to 127.0.0.1",
        C.H2: "sozu 1.1.1 advertises only http/1.1 in ALPN; its HTTP/2 frontend is compiled out",
        C.H3: "sozu has no QUIC listener",
        C.STATIC: NO_FILES,
    },
    template="sozu.toml",
    argv=_argv,
    tuning=(
        "worker_count = profile vCPUs; handle_process_affinity off (the harness pins with taskset)",
        "log_level warn (access logs are info level, so none are written); disable_cluster_metrics, no [metrics] sink",
        "max_connections 20000 per worker (default 10000): 10k idle TLS sessions can land on one worker",
        "max_buffers 40000 = 2 x max_connections, the vendor's sizing rule; buffer_size 16393 (default)",
        "front_timeout 60 s (default), back_timeout 60 s (default 30)",
        "backend connection is bound to each client session and reused across its keep-alive requests over HTTP/1.1; no pool or request cap to size",
        "listeners use SO_REUSEPORT per worker; backlog fixed at 1024 in sozu, not configurable",
        "https listener: TLS 1.3 only, default rustls cipher list, default 4 TLS 1.3 tickets",
    ),
    sources=(
        "https://github.com/sozu-proxy/sozu/blob/1.1.1/doc/configure.md",
        "https://github.com/sozu-proxy/sozu/blob/1.1.1/bin/config.toml",
        "https://github.com/sozu-proxy/sozu/blob/1.1.1/lib/src/https.rs",
        "https://github.com/sozu-proxy/sozu/blob/1.1.1/lib/src/tls.rs",
        "https://github.com/sozu-proxy/sozu/blob/1.1.1/lib/src/socket.rs",
    ),
)
