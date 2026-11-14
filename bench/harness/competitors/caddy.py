from ..servers import ALL, Server, exe

SERVER = Server(
    name="caddy",
    tool="caddy",
    capabilities=ALL,
    not_applicable={},
    template="Caddyfile",
    argv=lambda ctx: [exe("caddy"), "run", "--config", str(ctx.config), "--adapter", "caddyfile"],
    env=lambda ctx: {
        "GOMAXPROCS": str(ctx.workers),
        "XDG_CONFIG_HOME": str(ctx.run_dir),
        "XDG_DATA_HOME": str(ctx.run_dir),
    },
    tuning=(
        "GOMAXPROCS = profile vCPUs",
        "admin off, persist_config off; storage and XDG dirs in the run dir",
        "no access log; runtime log level WARN",
        "auto_https disable_redirects: no HTTP->HTTPS redirect and no listener on port 80",
        "tls with the given cert, protocols tls1.3; default ciphers and session tickets",
        "server idle timeout 75s; default protocols h1 h2 h3 with Alt-Svc sent by default",
        "reverse_proxy transport http versions 1.1, keepalive 75s, keepalive_idle_conns(_per_host) 256 (default per host is 32)",
        "bodies stream: request_buffers and response_buffers left at 0",
        "static: file_server rooted at the static dir",
    ),
    sources=(
        "https://caddyserver.com/docs/caddyfile/options",
        "https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#the-http-transport",
        "https://caddyserver.com/docs/caddyfile/directives/tls",
        "https://caddyserver.com/docs/automatic-https#activation",
        "https://caddyserver.com/docs/caddyfile/directives/file_server",
        "https://caddyserver.com/docs/conventions#data-directory",
        "https://pkg.go.dev/runtime#hdr-Environment_Variables",
    ),
)
