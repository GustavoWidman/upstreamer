# What a NixOS switch does to the proxy and to its clients. `server` runs upstreamer in front of
# a backend; `client` loads it over HTTP/1.1, HTTP/2 and HTTP/3 while the server switches to a
# specialisation:
# - `upgraded` changes nothing but the package, so the running proxy hands over to the new one;
# - `config` changes nothing but the config, so the proxy reloads in its process;
# - `unit` changes the unit, so systemd restarts it, with the listening sockets kept in its
#   file descriptor store;
# - `broken` has a package that cannot serve, `stuck` one that never gets ready, `speechless`
#   one that cannot even ask for the reload, and `unreadable` a config that does not load: the
#   reload fails, the switch fails with it, and the running proxy stays;
# - `mute` has a package whose reload command asks nothing and succeeds, as that of a version
#   that cannot talk to the running one does: systemd then signals the reload itself.
#
# With `seamless = false` only the package switch runs and nothing about it is asserted: the
# numbers it prints are what a switch costs with a module that restarts the proxy instead.
#
# h2load speaks HTTP/2 and HTTP/3 until the handover only: it opens no new connection after a
# GOAWAY and writes off the requests it had left for the old one, as failed. What it did send
# is checked against the proxy's access log; the client that follows a GOAWAY is curl.
{
  pkgs,
  lib,
  module,
  tls,
  seamless ? true,
  ...
}:
let
  python = pkgs.python3.withPackages (ps: [ ps.aiohttp ]);
  h2load = pkgs.nghttp2.override { enableHttp3 = true; };
  host = "app.example.test";
in
{
  name = "upstreamer-upgrade";

  nodes = {
    server =
      { options, ... }:
      let
        package = options.services.upstreamer.package.default;
        # The same program as another file in another store path. The appended bytes keep it
        # another file where the store links files of equal content together.
        next = pkgs.runCommand "upstreamer-next" { meta.mainProgram = "upstreamer"; } ''
          install -D ${lib.getExe package} "$out/bin/upstreamer"
          printf next >> "$out/bin/upstreamer"
        '';
        # A program that passes `passed` on to the real one and runs `otherwise` for the rest.
        # Each checks a config, as the module needs at build time.
        partial =
          passed: otherwise:
          pkgs.writeShellScriptBin "upstreamer" ''
            case "$1" in ${passed}) exec ${lib.getExe package} "$@" ;; esac
            ${otherwise}
          '';
        cannotRun = ''
          echo "this build cannot run" >&2
          exit 1
        '';
        # Asks for a reload, as the unit's reload command does, and cannot serve.
        broken = partial "check | reload" cannotRun;
        # Asks, and never reports that it is ready to serve.
        stuck = partial "check | reload" "exec sleep 600";
        # Cannot even ask.
        speechless = partial "check" cannotRun;
        # Serves, and its reload command succeeds without asking.
        mute = partial "check | run" "exit 0";
        # Not a config. The module checks the one it generates when it builds it, so this one
        # is put in its place, with the trigger that makes the switch reload.
        unreadable = pkgs.writeText "config.json" "{ not a config";
      in
      {
        imports = [ module ];
        virtualisation.cores = 2;
        # Room for the firewall to track the clients' connections.
        virtualisation.memorySize = 2048;
        services.upstreamer = {
          enable = true;
          virtualHosts.${host} = {
            tls = {
              certFile = "${tls}/cert.pem";
              keyFile = "${tls}/key.pem";
            };
            accessLog.enable = true;
            routes = [
              {
                when.path = "/local";
                respond.body = "local";
              }
            ];
            proxy = "http://127.0.0.1:8000";
          };
        };
        environment.systemPackages = [ pkgs.curl ];

        specialisation = {
          upgraded.configuration.services.upstreamer.package = next;
          # A route, and with the metrics a listener of their own.
          config.configuration.services.upstreamer = {
            metrics.enable = true;
            virtualHosts.${host}.routes = [
              {
                when.path = "/extra";
                respond.body = "extra";
              }
            ];
          };
          unit.configuration.systemd.services.upstreamer.environment.UPSTREAMER_TEST = "1";
          broken.configuration.services.upstreamer.package = broken;
          stuck.configuration.services.upstreamer.package = stuck;
          speechless.configuration.services.upstreamer.package = speechless;
          mute.configuration.services.upstreamer.package = mute;
          unreadable.configuration = {
            environment.etc."upstreamer/config.json".source = lib.mkForce unreadable;
            systemd.services.upstreamer.reloadTriggers = [ unreadable ];
          };
        };

        systemd.services.backend = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${lib.getExe python} ${./backend.py} 127.0.0.1 8000";
            DynamicUser = true;
          };
        };
      };

    client =
      { nodes, ... }:
      {
        virtualisation.cores = 2;
        # No firewall, so that this machine's kernel tracks no connection. A closed connection
        # stays in the tracking table for two minutes, the probes close enough of them to fill
        # it (7680 entries with this much memory), and the kernel then drops the machine's own
        # packets: a connect times out and a QUIC send fails for packets that never left.
        networking.firewall.enable = false;
        networking.hosts.${nodes.server.networking.primaryIPAddress} = [ host ];
        environment.systemPackages = [
          pkgs.curl
          pkgs.python3
          h2load
        ];
      };
  };

  testScript =
    { nodes, ... }:
    let
      upstreamer = system: system.services.upstreamer;
      program = system: lib.getExe (upstreamer system).package;
    in
    ''
      import json
      import re
      import time

      ca = "${tls}/ca.pem"
      url = "https://${host}"
      load = "python3 ${./upgrade-load.py}"
      access_log = "${(upstreamer nodes.server).virtualHosts.${host}.accessLog.path}"
      seamless = ${if seamless then "True" else "False"}
      programs = {
          "base": "${program nodes.server}",
          "upgraded": "${program nodes.server.specialisation.upgraded.configuration}",
      }

      # Clients that run until told to stop, and the outcome each counts as a success.
      PROBES = {
          "connect to 80": ("connect ${host} 80", "connected"),
          "connect to 443": ("connect ${host} 443", "connected"),
          "h1, a connection per request": (f"get --http1.1 {url}/v {ca}", "200"),
          "h1, one connection": (f"keep {url}/v {ca}", "200"),
          "h2, a connection per request": (f"get --http2 {url}/v {ca}", "200"),
          "h2, one connection": (f"batch --http2 {url}/v {ca}", "200"),
          "h3, a connection per request": (f"get --http3-only {url}/v {ca}", "200"),
          "h3, one connection": (f"batch --http3-only {url}/v {ca}", "200"),
      }
      # h2load's flags, and the protocol its requests have in the access log.
      H2LOAD = {
          "h2load h1": ("--h1 -c 8 -t 2", "HTTP/1.1"),
          "h2load h2": ("-c 8 -t 2 -m 8", "HTTP/2"),
          "h2load h3": ("--alpn-list=h3 -c 4 -t 2 -m 8", "HTTP/3"),
      }
      # The clients that speak HTTP/3: what they see is reported, not asserted.
      QUIC = ["h3, a connection per request", "h3, one connection", "h2load h3"]
      # The clients whose connection outlives a request: a stop closes it under them.
      KEPT = ["h1, one connection", "h2, one connection", "h3, one connection"]
      # The probes each load runs, by its tag.
      started = {}

      def curl(args):
          return client.succeed(f"curl -sf --cacert {ca} --max-time 10 {args}")

      def unit(prop):
          return server.succeed(f"systemctl show upstreamer.service -P {prop}").strip()

      def switch(specialisation=None):
          system = f"{base}/specialisation/{specialisation}" if specialisation else base
          server.succeed(f"{system}/bin/switch-to-configuration test >&2")

      def failed_switch(specialisation):
          """Switches to a system whose reload of the proxy fails: the switch fails and says
          that the proxy's unit did. Returns what the unit logged meanwhile."""
          since = server.succeed("date +%s").strip()
          system = f"{base}/specialisation/{specialisation}"
          status, output = server.execute(f"{system}/bin/switch-to-configuration test 2>&1")
          print(f"switch-to-configuration exited {status}:\n{output}")
          assert status != 0, f"the switch to {specialisation} succeeded"
          assert "Failed to reload upstreamer.service" in output, output
          return server.succeed(
              "journalctl --sync && "
              f"journalctl -u upstreamer.service --no-pager -o cat --since @{since}"
          )

      def generation():
          """The generation the unit's status says the proxy serves."""
          status = unit("StatusText")
          served = re.fullmatch(r"serving generation (\d+)", status)
          assert served, status
          return int(served[1])

      def program_of(pid):
          return server.succeed(f"readlink /proc/{pid}/exe").strip()

      def processes():
          procs = "/sys/fs/cgroup/system.slice/upstreamer.service/cgroup.procs"
          return server.succeed(f"cat {procs}").split()

      def stored():
          """The names in the unit's file descriptor store."""
          listing = server.succeed("systemd-analyze fdstore upstreamer.service 2>&1 || true")
          return sorted(set(re.findall(r"^((?:tcp|udp)_\S+)", listing, re.M)))

      def logged(proto):
          """The requests of h2load the proxy answered over `proto`: all of them, and those
          it did not answer with 200."""
          field = f'"proto":"{proto}","user_agent":"h2load'
          count = "grep -cF '{}' {} || true".format
          every = int(server.succeed(count(field, access_log)))
          bad = server.succeed(f"grep -F '{field}' {access_log} | grep -vcF '\"status\":200' || true")
          return every, int(bad)

      def refused(port):
          """Whether the server refuses a TCP connection to `port` (rather than taking it, or
          leaving it unanswered)."""
          status, _ = client.execute(f"curl -s -o /dev/null --max-time 5 http://${host}:{port}/")
          return status == 7

      def start_load(tag, seconds=None, probes=PROBES):
          """Starts `probes`, and h2load for `seconds` when given."""
          client.succeed(f"rm -rf /tmp/{tag} /tmp/stop && mkdir /tmp/{tag}")
          started[tag] = list(probes)
          for name in started[tag]:
              probe, _ = PROBES[name]
              client.succeed(
                  f"{load} {probe} /tmp/stop > '/tmp/{tag}/{name}.json' 2> '/tmp/{tag}/{name}.err' &"
              )
          before = {}
          for name, (flags, proto) in H2LOAD.items() if seconds else []:
              before[name] = logged(proto)
              client.succeed(
                  f"h2load {flags} -D {seconds} {url}/local > '/tmp/{tag}/{name}.txt' 2>&1 &"
              )
          server.succeed(
              "rm -f /tmp/sampled; (while [ ! -e /tmp/sampled ]; do"
              " systemctl show upstreamer.service -P ActiveState; sleep 0.1; done)"
              " > /tmp/states 2>&1 &"
          )
          return before

      def finish_load(tag, before):
          """What every client saw: per client, its attempts by outcome."""
          client.wait_until_fails("pgrep h2load", timeout=180)
          client.succeed("touch /tmp/stop")
          client.wait_until_fails("pgrep -f 'upgrade-loa[d].py'", timeout=60)
          server.succeed("touch /tmp/sampled")
          seen = {}
          for name in started[tag]:
              result = json.loads(client.succeed(f"cat '/tmp/{tag}/{name}.json'"))
              seen[name] = result["counts"]
              if result["first_failure"] is not None:
                  span = result["last_failure"] - result["first_failure"]
                  print(f"{tag}: {name}: failures over {span:.1f} s")
          # The access log is written once a second.
          time.sleep(3)
          for name, (_, proto) in H2LOAD.items() if before else []:
              text = client.succeed(f"cat '/tmp/{tag}/{name}.txt'")
              requests = re.search(
                  r"requests: \d+ total, \d+ started, \d+ done, (\d+) succeeded, (\d+) failed,"
                  r" (\d+) errored, (\d+) timeout",
                  text,
              )
              codes = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", text)
              assert requests and codes, text
              succeeded, failed, errored, timeout = map(int, requests.groups())
              ok, *others = map(int, codes.groups())
              answered, not_200 = (now - then for now, then in zip(logged(proto), before[name]))
              seen[name] = {
                  "succeeded": succeeded,
                  "2xx": ok,
                  "other status": sum(others),
                  "timeout": timeout,
                  "not started or failed": failed,
                  "answered by the proxy": answered,
                  "not answered with 200": not_200,
              }
          states = sorted(set(server.succeed("cat /tmp/states").split()))
          for name, counts in seen.items():
              print(f"{tag}: {name}: {counts}")
          print(f"{tag}: unit states seen: {states}")
          # A machine that dropped packets itself would pass for a proxy that left them
          # unanswered.
          for machine in [client, server]:
              full = machine.succeed("dmesg | grep -c 'nf_conntrack: table full' || true")
              assert full.strip() == "0", f"{machine.name} dropped packets: its connection table was full"
          return seen, states

      def assert_nothing_failed(seen, states, but=()):
          for name, (_, good) in PROBES.items():
              if name in seen and name not in QUIC and name not in but:
                  assert set(seen[name]) == {good}, f"{name}: {seen[name]}"
          for name in H2LOAD:
              if name in seen and name not in QUIC:
                  counts = seen[name]
                  # Every request the proxy got was answered 200, and h2load saw the answers:
                  # all but those under way when its time was up, at most one per stream.
                  answered = counts["answered by the proxy"]
                  assert 0 < counts["succeeded"] == counts["2xx"] <= answered, f"{name}: {counts}"
                  assert answered <= counts["succeeded"] + 64, f"{name}: {counts}"
                  assert not any(
                      counts[k] for k in ("other status", "timeout", "not answered with 200")
                  ), f"{name}: {counts}"
          # h2load reconnects over HTTP/1.1, so there none of its requests may be left out.
          if "h2load h1" in seen:
              assert seen["h2load h1"]["not started or failed"] == 0, seen["h2load h1"]
          assert set(states) <= {"active", "reloading"}, states

      start_all()
      server.wait_for_unit("upstreamer.service")
      server.wait_for_unit("backend.service")
      server.wait_for_open_port(443)
      server.wait_for_open_port(8000)
      client.wait_for_unit("multi-user.target")
      base = server.succeed("readlink -f /run/current-system").strip()
      print(server.succeed("systemctl --version | head -n1"))
      for flag in ["--http1.1", "--http2", "--http3-only"]:
          assert curl(f"{flag} {url}/local") == "local"

      with subtest("a switch to another package under load"):
          pid, invocation = unit("MainPID"), unit("InvocationID")
          assert program_of(pid) == programs["base"], program_of(pid)
          before = start_load("package", 40)
          client.succeed(f"{load} idle {url}/v {ca} > /tmp/idle.json 2> /tmp/idle.err &")
          time.sleep(8)
          switch("upgraded")
          new = unit("MainPID")
          status = server.succeed("systemctl status upstreamer.service --no-pager")
          print(status)
          if seamless:
              assert new != pid, "another process is the main one"
              assert program_of(new) == programs["upgraded"], program_of(new)
              assert unit("InvocationID") == invocation, "the unit was not restarted"
              assert unit("NRestarts") == "0"
              assert f"Main PID: {new}" in status and "active (running)" in status, status
              assert server.succeed(f"ps -o ppid= -p {new}").strip() == "1", "a child of systemd"
              server.wait_until_fails(f"test -e /proc/{pid}", timeout=30)
              assert unit("ActiveState") == "active" and unit("MainPID") == new
              assert processes() == [new], processes()
              journal = server.succeed("journalctl -b -u upstreamer.service --no-pager")
              print(journal)
              assert f"handed over to process {new}" in journal, journal
              assert "not our child" not in journal, journal
              # The reload command's exit ended the reload: systemd sent no signal after it,
              # which the new process would have answered with a second generation.
              assert unit("StatusText") == "serving generation 1", unit("StatusText")
              assert "serving generation 2" not in journal, journal
          client.wait_until_succeeds("test -s /tmp/idle.json", timeout=60)
          late = json.loads(client.succeed("cat /tmp/idle.json"))
          print(f"package: a connection idle between requests: {late}")
          seen, states = finish_load("package", before)
          print(f"package: main process {pid} -> {new}")
          if seamless:
              assert late.get("status") == 200 and late.get("closes"), (
                  f"a request on a connection kept from before the switch: {late}"
              )
              assert_nothing_failed(seen, states)

      if seamless:
          with subtest("stopping the unit during a handover stops both processes"):
              old = unit("MainPID")
              # A request that never ends keeps the old process draining.
              client.succeed(
                  "(exec 3<>/dev/tcp/${host}/80; printf 'GET / HTTP/1.1\\r\\n' >&3; sleep 60)"
                  " > /dev/null 2>&1 &"
              )
              time.sleep(1)
              switch()
              new = unit("MainPID")
              assert new != old and {old, new} <= set(processes()), processes()
              server.succeed("systemctl stop upstreamer.service")
              server.fail(f"test -e /proc/{old}")
              server.fail(f"test -e /proc/{new}")
              assert unit("ActiveState") == "inactive", unit("ActiveState")
              assert unit("Result") == "success", unit("Result")
              assert refused(80) and refused(443), "a stopped unit holds no port"
              server.succeed("systemctl start upstreamer.service")
              server.wait_for_open_port(443)
              assert curl(f"{url}/local") == "local"

          with subtest("a switch that changes only the config reloads in the process"):
              pid, invocation = unit("MainPID"), unit("InvocationID")
              kept = stored()
              print(f"file descriptor store: {kept}")
              assert "tcp_0.0.0.0_443" in kept and "udp_0.0.0.0_443" in kept, kept
              client.fail(f"curl -sf --cacert {ca} {url}/extra | grep -x extra")
              before = generation()
              switch("config")
              assert (unit("MainPID"), unit("InvocationID")) == (pid, invocation)
              assert processes() == [pid], processes()
              assert curl(f"{url}/extra") == "extra"
              assert generation() == before + 1, "one reload, by the command alone"
              server.succeed("curl -sf http://127.0.0.1:9100/metrics > /dev/null")
              time.sleep(1)
              assert "tcp_127.0.0.1_9100" in stored(), stored()
              switch()
              assert (unit("MainPID"), unit("InvocationID")) == (pid, invocation)
              time.sleep(1)
              assert stored() == kept, "a listener the reload removed leaves the store"
              code, _ = server.execute("curl -s -o /dev/null --max-time 5 http://127.0.0.1:9100/")
              assert code == 7, f"its port is closed, not held: curl exit {code}"

          with subtest("a SIGHUP sent by hand reloads"):
              before = generation()
              server.succeed(f"kill -HUP {pid}")
              server.wait_until_succeeds(
                  "systemctl show upstreamer.service -P StatusText"
                  f" | grep -x 'serving generation {before + 1}'"
              )
              assert unit("ActiveState") == "active" and unit("MainPID") == pid

          with subtest("a switch that changes the unit restarts it, with nothing refused"):
              start_load("unit")
              time.sleep(4)
              switch("unit")
              restarted = unit("MainPID")
              assert restarted != pid and unit("InvocationID") != invocation
              environment = server.succeed(f"tr '\\0' '\\n' < /proc/{restarted}/environ")
              assert "UPSTREAMER_TEST=1" in environment, environment
              time.sleep(4)
              seen, states = finish_load("unit", None)
              # A restart closes the kept connections; no new one is refused or left unanswered.
              for name, (_, good) in PROBES.items():
                  if name not in QUIC and name not in KEPT:
                      assert set(seen[name]) == {good}, f"{name}: {seen[name]}"
              assert stored() == kept, stored()
              assert curl(f"{url}/local") == "local"

          with subtest("a crash refuses no connection"):
              # A killed process says nothing to a client whose connection it had, and over
              # QUIC that client only finds out by waiting, so the kept connections stay out.
              start_load("crash", probes=[name for name in PROBES if name not in KEPT])
              time.sleep(4)
              crashed = unit("MainPID")
              server.succeed(f"kill -KILL {crashed}")
              server.wait_until_succeeds(
                  f"test \"$(systemctl show upstreamer.service -P MainPID)\" != {crashed}"
                  " && systemctl is-active upstreamer.service"
              )
              time.sleep(4)
              seen, states = finish_load("crash", None)
              assert int(unit("NRestarts")) >= 1, unit("NRestarts")
              for name in ["connect to 80", "connect to 443"]:
                  assert set(seen[name]) == {"connected"}, f"{name}: {seen[name]}"
              assert curl(f"{url}/local") == "local"
              switch()
              server.wait_for_open_port(443)

          def serving_as_before(pid, invocation):
              assert (unit("MainPID"), unit("InvocationID")) == (pid, invocation)
              assert unit("ActiveState") == "active", unit("ActiveState")
              assert unit("NRestarts") == restarts, "the unit was not restarted"
              assert processes() == [pid], processes()
              assert curl(f"{url}/local") == "local"

          restarts = unit("NRestarts")
          with subtest("a package that cannot serve fails the switch and leaves the running one serving"):
              pid, invocation = unit("MainPID"), unit("InvocationID")
              serving = generation()
              before = start_load("broken", 15)
              time.sleep(5)
              said = failed_switch("broken")
              reason = (
                  f"reload failed, still serving generation {serving}:"
                  " cannot hand over to /etc/upstreamer/upstreamer: it exited before it was ready"
              )
              assert f"upstreamer: {reason}" in said, "the reload command says why"
              assert unit("StatusText") == reason, unit("StatusText")
              serving_as_before(pid, invocation)
              seen, states = finish_load("broken", before)
              assert_nothing_failed(seen, states)
              for name in QUIC:
                  bad = {
                      k: v
                      for k, v in seen[name].items()
                      if k not in ("200", "succeeded", "2xx", "answered by the proxy")
                  }
                  assert not any(bad.values()), f"{name}: {seen[name]}"
              server.fail("systemctl reload upstreamer.service")
              serving_as_before(pid, invocation)
              switch()
              assert unit("MainPID") == pid
              assert generation() > serving, "the next reload goes through"

          with subtest("a config that does not load fails the switch the same way"):
              serving = generation()
              start_load("unreadable")
              time.sleep(4)
              said = failed_switch("unreadable")
              reason = f"reload failed, still serving generation {serving}: "
              assert f"upstreamer: {reason}" in said, said
              assert unit("StatusText").startswith(reason), unit("StatusText")
              serving_as_before(pid, invocation)
              time.sleep(2)
              seen, states = finish_load("unreadable", None)
              assert_nothing_failed(seen, states)
              switch()
              assert unit("MainPID") == pid
              assert generation() > serving, "the next reload goes through"

          with subtest("a package that cannot ask for the reload fails the switch"):
              serving = generation()
              said = failed_switch("speechless")
              assert "this build cannot run" in said, said
              assert unit("StatusText") == f"serving generation {serving}", "nothing was tried"
              serving_as_before(pid, invocation)
              switch()

          with subtest("a package that never gets ready fails the switch before systemd gives up on the reload"):
              serving = generation()
              began = time.monotonic()
              said = failed_switch("stuck")
              took = time.monotonic() - began
              reason = (
                  f"reload failed, still serving generation {serving}:"
                  " cannot hand over to /etc/upstreamer/upstreamer: not ready after 30 s"
              )
              assert f"upstreamer: {reason}" in said, said
              assert "timed out" not in said, "the proxy gave up, not systemd"
              assert 30 <= took < 60, f"the switch waited {took:.0f} s"
              assert unit("TimeoutStartUSec") == "1min 30s", unit("TimeoutStartUSec")
              serving_as_before(pid, invocation)
              switch()

          with subtest("a reload command that asks nothing leaves the reload to systemd's signal"):
              switch("mute")
              signalled = unit("MainPID")
              assert signalled != pid and unit("InvocationID") == invocation
              server.wait_until_fails(f"test -e /proc/{pid}", timeout=30)
              assert unit("ActiveState") == "active" and unit("NRestarts") == restarts
              assert curl(f"{url}/local") == "local"
              journal = server.succeed("journalctl -b -u upstreamer.service --no-pager -o cat")
              assert f"handed over to process {signalled}" in journal, journal
              switch()
              assert unit("ActiveState") == "active"
              assert curl(f"{url}/local") == "local"
    '';
}
