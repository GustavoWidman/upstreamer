# The proxy on a booted host, seen from another machine: `server` runs upstreamer in front of a
# backend (HTTP and a WebSocket echo) with a certificate from files; `client` reaches it only
# through the server's firewall. The `extra` specialisation changes nothing but the proxy's
# routes, so switching to it reloads the proxy.
{
  pkgs,
  lib,
  module,
  tls,
  ...
}:
let
  python = pkgs.python3.withPackages (ps: [ ps.aiohttp ]);
  host = "app.example.test";
in
{
  name = "upstreamer-proxy";

  nodes = {
    server = {
      imports = [ module ];
      services.upstreamer = {
        enable = true;
        virtualHosts.${host} = {
          tls = {
            certFile = "${tls}/cert.pem";
            keyFile = "${tls}/key.pem";
          };
          proxy = "http://127.0.0.1:8000";
        };
      };
      specialisation.extra.configuration.services.upstreamer.virtualHosts.${host}.routes = [
        {
          when.path = "/extra";
          respond.body = "extra";
        }
      ];

      # On every address, so the firewall is all that keeps the client from reaching it.
      systemd.services.backend = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = "${lib.getExe python} ${./backend.py} 0.0.0.0 8000";
          DynamicUser = true;
        };
      };
    };

    client =
      { nodes, ... }:
      {
        networking.hosts.${nodes.server.networking.primaryIPAddress} = [ host ];
        environment.systemPackages = [
          pkgs.curl
          python
        ];
      };
  };

  testScript = ''
    import re
    import time

    ca = "${tls}/ca.pem"
    url = "https://${host}"

    def curl(args):
        return client.succeed(f"curl -sf --cacert {ca} --max-time 10 {args}")

    def unit(prop):
        return server.succeed(f"systemctl show upstreamer.service -P {prop}").strip()

    start_all()
    server.wait_for_unit("upstreamer.service")
    server.wait_for_unit("backend.service")
    server.wait_for_open_port(443)
    server.wait_for_open_port(8000)
    client.wait_for_unit("multi-user.target")

    with subtest("h1, h2 and h3 reach the backend"):
        for flag, version in [("--http1.1", "1.1"), ("--http2", "2"), ("--http3-only", "3")]:
            out = curl(f"{flag} -w '\\n%{{http_version}}' {url}/v?q=1")
            body, seen = out.rsplit("\n", 1)
            assert seen == version, f"{flag}: answered over HTTP/{seen}"
            assert body == "backend GET /v?q=1", f"{flag}: {body}"
        alt_svc = curl(f"--http2 -D - -o /dev/null {url}/").lower()
        assert 'alt-svc: h3=":443"' in alt_svc, alt_svc

    with subtest("plain HTTP is redirected to HTTPS"):
        out = client.succeed(
            "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' 'http://${host}/a/b?c=d'"
        )
        assert out == "308 https://${host}/a/b?c=d", out

    with subtest("a WebSocket upgrade is proxied both ways"):
        client.succeed(f"python3 ${./websocket.py} wss://${host}/ws {ca}")

    with subtest("a config switch reloads the proxy without failing a request"):
        client.fail(f"curl -sf --cacert {ca} {url}/extra | grep -x extra")
        pid = unit("MainPID")
        client.succeed(
            f"(python3 ${./load.py} {url}/ {ca} /tmp/stop; echo $? > /tmp/load.rc)"
            " > /tmp/load.log 2>&1 &"
        )
        time.sleep(2)
        server.succeed("/run/current-system/specialisation/extra/bin/switch-to-configuration test")
        server.wait_until_succeeds("systemctl is-active upstreamer.service")
        assert curl(f"{url}/extra") == "extra"
        time.sleep(2)
        client.succeed("touch /tmp/stop")
        client.wait_for_file("/tmp/load.rc")
        log = client.succeed("cat /tmp/load.log")
        print(log)
        assert client.succeed("cat /tmp/load.rc").strip() == "0", log
        assert unit("MainPID") == pid, "reloaded, not restarted"

    with subtest("hardening: an unprivileged process binds :80 and :443 with one capability"):
        print(server.succeed("systemd-analyze security --no-pager upstreamer.service"))
        overall = server.succeed("systemd-analyze security --no-pager upstreamer.service | tail -n1")
        score, rating = re.search(r"([0-9.]+) (\w+)", overall.split(":", 1)[1]).groups()
        print(f"systemd-analyze security exposure: {score} {rating}")
        assert rating in ("SAFE", "OK"), overall
        pid = unit("MainPID")
        assert server.succeed(f"stat -c %u /proc/{pid}").strip() != "0", "runs as root"
        cap_eff = server.succeed(f"grep CapEff /proc/{pid}/status").split()[1]
        assert int(cap_eff, 16) == 1 << 10, f"CapEff {cap_eff}: only CAP_NET_BIND_SERVICE"
        for proto, port in [("t", 80), ("t", 443), ("u", 443)]:
            sockets = server.succeed(f"ss -Hl{proto}np 'sport = :{port}'")
            assert f"pid={pid}," in sockets, f"{proto} {port}: {sockets}"

    with subtest("the firewall opens the proxy's ports and nothing else"):
        server.succeed("curl -sf http://127.0.0.1:8000/")
        client.fail("curl -s --connect-timeout 3 http://server:8000/")
  '';
}
