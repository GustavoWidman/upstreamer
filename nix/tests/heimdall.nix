# heimdall's virtual host through upstreamer: the routes and headers of heimdall's NixOS module
# (tests/differential/fleet/heimdall-module.nix) over a web build shaped like heimdall's and a
# stub of its API. The assertions are those heimdall's own VM test makes of its proxy.
{
  pkgs,
  lib,
  module,
  tls,
  ...
}:
let
  host = "heimdall.example.test";
  web = pkgs.runCommand "heimdall-web-fixture" {
    nativeBuildInputs = [ (pkgs.python3.withPackages (ps: [ ps.brotli ])) ];
  } ''python3 ${./heimdall-web.py} "$out"'';
in
{
  name = "upstreamer-heimdall";

  nodes.machine = {
    imports = [
      module
      ../../tests/differential/fleet/heimdall-module.nix
    ];
    networking.hosts."127.0.0.1" = [ host ];

    services.heimdall = {
      enable = true;
      package = {
        type = "derivation";
        name = "heimdall";
        outPath = "/nonexistent";
        inherit web;
      };
      virtualHost = host;
    };
    services.upstreamer.virtualHosts.${host}.tls = {
      certFile = "${tls}/cert.pem";
      keyFile = "${tls}/key.pem";
    };

    systemd.services.heimdall-api = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${lib.getExe pkgs.python3} ${./heimdall-api.py}";
        DynamicUser = true;
      };
    };
  };

  testScript = ''
    import json

    base = "https://${host}"
    curl = "curl -sf --cacert ${tls}/ca.pem"

    machine.wait_for_unit("upstreamer.service")
    machine.wait_for_unit("heimdall-api.service")
    machine.wait_for_open_port(443)
    machine.wait_for_open_port(7979)

    with subtest("/api is proxied to the server"):
        machine.succeed(f"{curl} {base}/api/health")
        headers = machine.succeed(
            f"{curl} -D - -o /dev/null -H 'content-type: application/json' "
            f"-d '{{\"password\":\"hunter2\"}}' {base}/api/login"
        )
        cookie = next(
            line.split(":", 1)[1].split(";")[0].strip()
            for line in headers.splitlines()
            if line.lower().startswith("set-cookie:")
        )
        op = '{"hlc":"0000lkx9a0001a1b2c3d4e5","kind":"mark","id":"m_1","set":{"at":1}}'
        sync = lambda url: json.loads(machine.succeed(
            f"{curl} -H 'cookie: {cookie}' -H 'content-type: application/json' "
            f"-d '{{\"after\":0,\"ops\":[{op}]}}' {url}/api/sync"
        ))
        proxied, direct = sync(base), sync("http://127.0.0.1:7979")
        assert proxied == direct, (proxied, direct)
        assert proxied["ops"] == [{"seq": 1, "op": json.loads(op)}], proxied

    with subtest("client routes are answered with the app shell"):
        machine.succeed(f"{curl} {base}/day/2026-11-09 | grep -q '<html'")

    with subtest("the shell: precompressed, revalidated by its content-hash ETag, with security headers"):
        raw = machine.succeed(f"{curl} -D - -o /dev/null -H 'accept-encoding: br' {base}/day/2026-11-09")
        index = raw.lower()
        assert "cache-control: no-cache" in index, index
        assert "content-encoding: br" in index, index
        assert "x-content-type-options: nosniff" in index, index
        assert "x-frame-options: deny" in index, index
        assert "\nserver:" not in index, index
        assert "last-modified:" not in index, index
        # ETags compare byte for byte, so read it before lowercasing.
        etag = next(l.split(":", 1)[1].strip() for l in raw.splitlines() if l.lower().startswith("etag:"))
        assert len(etag) == 26 and etag.startswith('"'), f"a content-hash ETag: {etag}"
        assert etag == machine.succeed("cat ${web}/index.html.br.etag"), etag
        unchanged = machine.succeed(
            f"curl -s --cacert ${tls}/ca.pem -o /dev/null -w '%{{http_code}}' -H 'accept-encoding: br' "
            f"-H 'if-none-match: {etag}' {base}/"
        )
        assert unchanged == "304", unchanged

    with subtest("immutable assets are cached for a year; missing ones and sidecars are 404"):
        headers = machine.succeed(f"{curl} -D - -o /dev/null {base}/_app/immutable/entry/start.Bx9e0f.js").lower()
        assert "max-age=31536000, immutable" in headers, headers
        machine.fail(f"{curl} {base}/_app/immutable/missing.js")
        machine.fail(f"{curl} {base}/index.html.etag")
  '';
}
