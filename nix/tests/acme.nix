# Certificates from a test ACME server. `acme` runs pebble and pebble-challtestsrv (the DNS
# server pebble resolves DNS-01 challenges with); `server` runs upstreamer with three hosts:
#
# - good.example.test: issued by pebble. validMinDays above pebble's lifetime makes every run of
#   its order-renew unit a renewal.
# - bad.example.test: its DNS hook always fails, so its issuance never succeeds.
# - pending.example.test: certificate files that never exist.
#
# The server boots before the ACME server, so the first issuance attempt fails as it does on a
# new host whose DNS is not ready.
{
  pkgs,
  lib,
  module,
  ...
}:
let
  names = [
    "good.example.test"
    "bad.example.test"
    "pending.example.test"
  ];

  dnsHook = pkgs.writeShellScript "dns-hook" ''
    set -euo pipefail
    if [ "$1" = present ]; then
      ${lib.getExe pkgs.curl} -sf --data '{"host": "'"$2"'", "value": "'"$3"'"}' http://acme.test:8055/set-txt
    else
      ${lib.getExe pkgs.curl} -sf --data '{"host": "'"$2"'"}' http://acme.test:8055/clear-txt
    fi
  '';
  legoEnv =
    hook:
    pkgs.writeText "lego.env" ''
      EXEC_PATH=${hook}
      EXEC_POLLING_INTERVAL=1
      EXEC_PROPAGATION_TIMEOUT=1
      EXEC_SEQUENCE_INTERVAL=1
    '';

  backendRoot = pkgs.writeTextDir "index.html" "backend";
in
{
  name = "upstreamer-acme";

  nodes = {
    acme =
      { nodes, ... }:
      {
        imports = [ "${pkgs.path}/nixos/tests/common/acme/server" ];
        networking.nameservers = lib.mkForce [ "127.0.0.1" ];
        networking.firewall.allowedTCPPorts = [
          53
          8055
        ];
        networking.firewall.allowedUDPPorts = [ 53 ];
        systemd.services.pebble-challtestsrv = {
          wantedBy = [ "multi-user.target" ];
          before = [ "pebble.service" ];
          serviceConfig = {
            ExecStart = "${pkgs.pebble}/bin/pebble-challtestsrv -dnsserver :53 -management :8055 -defaultIPv6 '' -defaultIPv4 ${nodes.server.networking.primaryIPAddress}";
            AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
          };
        };
      };

    server =
      { nodes, ... }:
      {
        imports = [
          module
          "${pkgs.path}/nixos/tests/common/acme/client"
        ];
        networking.hosts."127.0.0.1" = names;
        # lego finds each challenge's zone through the resolver: pebble-challtestsrv's DNS.
        networking.nameservers = lib.mkForce [ nodes.acme.networking.primaryIPAddress ];
        environment.systemPackages = [
          pkgs.openssl
          pkgs.python3
        ];

        security.acme.defaults = {
          dnsProvider = "exec";
          dnsPropagationCheck = false;
          environmentFile = legoEnv dnsHook;
        };
        security.acme.certs."good.example.test".validMinDays = 9999;
        # Certificates of one ACME account wait for the account's first certificate to be
        # issued, so the failing one gets an account of its own.
        security.acme.certs."bad.example.test" = {
          environmentFile = legoEnv "${pkgs.coreutils}/bin/false";
          email = "bad@example.test";
        };

        services.upstreamer = {
          enable = true;
          virtualHosts =
            lib.genAttrs names (_: {
              proxy = "http://127.0.0.1:8000";
            })
            // {
              "pending.example.test" = {
                proxy = "http://127.0.0.1:8000";
                tls = {
                  certFile = "/run/missing/cert.pem";
                  keyFile = "/run/missing/key.pem";
                };
              };
            };
        };

        systemd.services.backend = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${lib.getExe pkgs.python3} -m http.server --bind 127.0.0.1 --directory ${backendRoot} 8000";
            DynamicUser = true;
          };
        };
      };
  };

  testScript = ''
    import time

    def served(name, field):
        return server.succeed(
            f"openssl s_client -connect 127.0.0.1:443 -servername {name} </dev/null 2>/dev/null"
            f" | openssl x509 -noout -{field}"
        ).strip()

    def on_disk(name):
        return server.succeed(
            f"openssl x509 -noout -fingerprint -sha256 -in /var/lib/acme/{name}/cert.pem"
        ).strip()

    def wait_served(name, predicate, what):
        for _ in range(60):
            fingerprint = served(name, "fingerprint -sha256")
            if predicate(fingerprint):
                return fingerprint
            time.sleep(1)
        raise AssertionError(f"{name}: {what}; serving {fingerprint}")

    def serving_pebble(name):
        return "pebble" in served(name, "issuer").lower()

    def get(name, ca="-k"):
        return server.succeed(f"curl -sf {ca} https://{name}/")

    def get_verified(name):
        # pebble dates a certificate from the acme machine's clock, which the server's does not
        # follow (test machines run no time sync), so a new certificate can start a second in
        # the server's future. Its chain on disk verifies once it has started.
        server.wait_until_succeeds(
            f"openssl verify -CAfile /tmp/ca.pem -untrusted /var/lib/acme/{name}/chain.pem"
            f" /var/lib/acme/{name}/cert.pem",
            timeout=10,
        )
        return get(name, "--cacert /tmp/ca.pem")

    def unit(prop):
        return server.succeed(f"systemctl show upstreamer.service -P {prop}").strip()

    server.start()
    server.wait_for_unit("upstreamer.service")
    server.wait_for_open_port(443)
    first_pid = unit("MainPID")

    with subtest("before any issuance, every host is answered and the unit has not failed"):
        for name in ["good.example.test", "bad.example.test", "pending.example.test"]:
            assert not serving_pebble(name), f"{name} has no issued certificate yet"
            assert get(name) == "backend", name
        subject, issuer = served("pending.example.test", "subject"), served("pending.example.test", "issuer")
        assert "pending.example.test" in subject, subject
        assert issuer.removeprefix("issuer=") == subject.removeprefix("subject="), f"self-signed: {issuer} / {subject}"
        server.fail("systemctl is-failed upstreamer.service")
        assert unit("NRestarts") == "0"

    acme.start()
    acme.wait_for_unit("pebble.service")
    acme.wait_for_open_port(443)
    acme.wait_for_open_port(53)

    # lego saves an account key before it reaches the ACME server and, finding that key on its
    # next run, looks the account up instead of registering it; the boot-time attempt that never
    # reached pebble leaves such keys behind.
    server.succeed("systemctl stop acme-order-renew-good.example.test.service acme-order-renew-bad.example.test.service")
    server.succeed("rm -rf /var/lib/acme/.lego/accounts/*")

    with subtest("issuance: the proxy serves the issued chain after the renewal hook reloads it"):
        server.succeed("systemctl restart acme-order-renew-good.example.test.service")
        issued = on_disk("good.example.test")
        wait_served("good.example.test", lambda f: f == issued, "the issued certificate")
        server.succeed("curl -sf https://acme.test:15000/roots/0 > /tmp/ca.pem")
        assert get_verified("good.example.test") == "backend"
        assert unit("MainPID") == first_pid, "reloaded, not restarted"

    with subtest("a forced renewal swaps the chain without dropping a keep-alive connection"):
        server.succeed(
            "(python3 ${./keepalive.py} good.example.test /tmp/swapped /tmp/stop; echo $? > /tmp/keepalive.rc)"
            " > /tmp/keepalive.log 2>&1 &"
        )
        time.sleep(2)
        server.fail("test -e /tmp/keepalive.rc")
        server.succeed("systemctl start acme-order-renew-good.example.test.service")
        renewed = on_disk("good.example.test")
        assert renewed != issued, "the order-renew run renewed the certificate"
        wait_served("good.example.test", lambda f: f == renewed, "the renewed certificate")
        server.succeed("touch /tmp/swapped")
        time.sleep(1)
        server.succeed("touch /tmp/stop")
        server.wait_for_file("/tmp/keepalive.rc")
        keepalive_log = server.succeed("cat /tmp/keepalive.log")
        print(keepalive_log)
        assert server.succeed("cat /tmp/keepalive.rc").strip() == "0", keepalive_log
        assert unit("MainPID") == first_pid, "reloaded, not restarted"

    with subtest("a host whose issuance fails keeps the others serving"):
        server.fail("systemctl restart acme-order-renew-bad.example.test.service")
        server.succeed("systemctl reload upstreamer.service")
        assert served("good.example.test", "fingerprint -sha256") == renewed
        assert get_verified("good.example.test") == "backend"
        assert not serving_pebble("bad.example.test")
        assert get("bad.example.test") == "backend"
        server.fail("systemctl is-failed upstreamer.service")
        assert unit("MainPID") == first_pid
        assert unit("NRestarts") == "0"
  '';
}
