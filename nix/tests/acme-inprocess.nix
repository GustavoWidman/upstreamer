# Certificates issued in process (`tls.acme`) by a test ACME server. `acme` runs pebble, whose
# certificates live 90 seconds and whose front end rejects a tenth of the nonces; `server` runs
# upstreamer with two hosts, one validated over HTTP-01 and one over TLS-ALPN-01.
#
# The server boots before the ACME server, so the first orders fail and are retried a minute
# later, as on a host whose CA is not reachable yet. Then: the issued chains served without a
# restart, private state files, a renewal two thirds into the certificate's life, and a restart
# that serves the stored certificates from its first handshake.
{
  pkgs,
  lib,
  module,
  tls,
  ...
}:
let
  names = {
    "http.example.test" = "http-01";
    "alpn.example.test" = "tls-alpn-01";
  };
  testCerts = import "${pkgs.path}/nixos/tests/common/acme/server/snakeoil-certs.nix";
  pebbleConfig = pkgs.writeText "pebble.json" (
    builtins.toJSON {
      pebble = {
        listenAddress = "0.0.0.0:443";
        managementListenAddress = "0.0.0.0:15000";
        certificate = testCerts.${testCerts.domain}.cert;
        privateKey = testCerts.${testCerts.domain}.key;
        httpPort = 80;
        tlsPort = 443;
        ocspResponderURL = "";
        strict = true;
        profiles.default = {
          description = "short-lived, to see a renewal";
          validityPeriod = 90;
        };
      };
    }
  );
in
{
  name = "upstreamer-acme-inprocess";

  nodes = {
    acme =
      { nodes, ... }:
      {
        imports = [ "${pkgs.path}/nixos/tests/common/acme/server" ];
        # Pebble's validation resolves the names through /etc/hosts.
        networking.hosts.${nodes.server.networking.primaryIPAddress} = lib.attrNames names;
        systemd.services.pebble = {
          environment.PEBBLE_WFE_NONCEREJECT = lib.mkForce "10";
          serviceConfig.ExecStart = lib.mkForce "${pkgs.pebble}/bin/pebble -config ${pebbleConfig}";
        };
      };

    server =
      { nodes, ... }:
      {
        imports = [ module ];
        networking.hosts."127.0.0.1" = lib.attrNames names;
        # The ACME client verifies pebble's front end against the system trust store.
        security.pki.certificateFiles = [ nodes.acme.test-support.acme.caCert ];
        environment.systemPackages = [ pkgs.openssl ];

        services.upstreamer = {
          enable = true;
          # Sites in the config's own schema replace the module's virtual hosts. This host is
          # never served: it gives the module the ports the sites below listen on, which the
          # build-time check compares with the ones the compiler derives.
          virtualHosts."ports.example.test".tls = {
            certFile = "${tls}/cert.pem";
            keyFile = "${tls}/key.pem";
          };
          settings.sites = lib.mapAttrsToList (host: challenge: {
            name = host;
            hosts = [ host ];
            tls.acme = {
              email = "ops@example.test";
              directory = "https://${nodes.acme.test-support.acme.caDomain}/dir";
              inherit challenge;
            };
            routes = [ { respond.body = "served by ${host}"; } ];
          }) names;
        };
        systemd.services.upstreamer.serviceConfig.StateDirectory = "upstreamer";
      };
  };

  testScript = ''
    import time

    names = ["http.example.test", "alpn.example.test"]

    def served(name, field):
        return server.succeed(
            f"openssl s_client -connect 127.0.0.1:443 -servername {name} </dev/null 2>/dev/null"
            f" | openssl x509 -noout -{field}"
        ).strip()

    def wait_served(name, predicate, what, limit=150):
        for _ in range(limit):
            fingerprint = served(name, "fingerprint -sha256")
            if predicate(fingerprint):
                return fingerprint
            time.sleep(1)
        raise AssertionError(f"{name}: {what}; serving {fingerprint}")

    def from_pebble(name):
        return "pebble" in served(name, "issuer").lower()

    def stored(name):
        return server.succeed(
            f"openssl x509 -noout -fingerprint -sha256 -in /var/lib/upstreamer/acme/acme.test_dir/certificates/{name}/fullchain.pem"
        ).strip()

    def unit(prop):
        return server.succeed(f"systemctl show upstreamer.service -P {prop}").strip()

    server.start()
    server.wait_for_unit("upstreamer.service")
    server.wait_for_open_port(443)
    first_pid = unit("MainPID")

    with subtest("without a reachable CA, every host is served a self-signed certificate"):
        for name in names:
            subject, issuer = served(name, "subject"), served(name, "issuer")
            assert name in subject, subject
            assert issuer.removeprefix("issuer=") == subject.removeprefix("subject="), f"{issuer} / {subject}"
            assert server.succeed(f"curl -sfk https://{name}/") == f"served by {name}"
        server.wait_until_succeeds("journalctl -u upstreamer.service | grep -q 'acme: http.example.test: .*retrying in 60s'")

    acme.start()
    acme.wait_for_unit("pebble.service")
    acme.wait_for_open_port(443)

    with subtest("both challenge types issue, and the chains are served without a restart"):
        issued = {}
        for name in names:
            wait_served(name, lambda _: from_pebble(name), "a certificate from pebble")
            issued[name] = served(name, "fingerprint -sha256")
            assert issued[name] == stored(name), "served what the state directory holds"
        server.succeed("curl -sf https://acme.test:15000/roots/0 > /tmp/root.pem")
        for name in names:
            assert server.succeed(f"curl -sf --cacert /tmp/root.pem https://{name}/") == f"served by {name}"
        assert unit("MainPID") == first_pid
        assert unit("NRestarts") == "0"

    with subtest("keys are readable by the service only"):
        for key in ["accounts/ops@example.test.pem"] + [f"certificates/{n}/key.pem" for n in names]:
            mode = server.succeed(f"stat -L -c %a /var/lib/upstreamer/acme/acme.test_dir/{key}").strip()
            assert mode == "600", f"{key}: {mode}"
        for directory in ["acme", "acme/acme.test_dir", "acme/acme.test_dir/accounts"]:
            mode = server.succeed(f"stat -L -c %a /var/lib/upstreamer/{directory}").strip()
            assert mode == "700", f"{directory}: {mode}"

    with subtest("a certificate is renewed two thirds into its 90 s life, in the same process"):
        for name in names:
            renewed = wait_served(name, lambda f: f != issued[name] and from_pebble(name), "a renewed certificate", limit=120)
            issued[name] = renewed
        assert unit("MainPID") == first_pid

    with subtest("a restart serves the stored certificates from its first handshake"):
        server.succeed("systemctl restart upstreamer.service")
        server.wait_for_open_port(443)
        for name in names:
            assert served(name, "fingerprint -sha256") == stored(name)
            assert from_pebble(name)
  '';
}
