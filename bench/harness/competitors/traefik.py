from ..scenarios import Capability as C
from ..servers import ALL, NO_FILES, TEMPLATES, Context, Server, exe, render


def _argv(ctx: Context) -> list[str]:
    dynamic = (TEMPLATES / "traefik-dynamic.yml").read_text()
    (ctx.run_dir / "traefik-dynamic.yml").write_text(render(dynamic, ctx.values()))
    return [exe("traefik"), f"--configFile={ctx.config}"]


SERVER = Server(
    name="traefik",
    tool="traefik",
    capabilities=ALL - {C.STATIC},
    not_applicable={C.STATIC: NO_FILES},
    template="traefik.yml",
    argv=_argv,
    env=lambda ctx: {"GOMAXPROCS": str(ctx.workers)},
    tuning=(
        "GOMAXPROCS = profile vCPUs",
        "no accessLog, api, metrics or ping; log level WARN; version check and usage reporting off",
        "entryPoint idleTimeout 75s; readTimeout and keepAliveMaxRequests at defaults (60s, unlimited)",
        "serversTransport maxIdleConnsPerHost 256 (default 200)",
        "TLS option minVersion VersionTLS13; default cipher suites and ALPN h2, http/1.1",
        "default store defaultCertificate, served when no SNI matches",
        "http3 on the TLS entryPoint; Alt-Svc advertised by default",
        "file provider with watch off",
    ),
    sources=(
        "https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/",
        "https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/",
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/serverstransport/",
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-options/",
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-certificates/",
        "https://doc.traefik.io/traefik/reference/install-configuration/providers/others/file/",
        "https://pkg.go.dev/runtime#hdr-Environment_Variables",
    ),
)
