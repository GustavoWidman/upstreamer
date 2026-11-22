# Checks of the NixOS module on the example hosts.
#
# module-eval evaluates them, without building anything, and checks what the module derives
# from their virtual hosts: the config it emits (equal to tests/fixtures/config, which the Rust
# schema tests read), the ACME certificates and their names and groups, the unit, the firewall
# and the kernel modules. Each host's whole system is instantiated too, so a type error anywhere
# in the module fails here. It also evaluates misconfigured hosts and checks that the module's
# assertions reject each one with its message. It evaluates option cases too (metrics,
# Kubernetes, in-process ACME, trusted proxies) and checks what each derives: the config's
# pieces, the ports `check` expects and the firewall opens, the unit's credential and state
# directory. The hosts get a stub package, so evaluating them for another system needs nothing
# built for it. `fixtures` in the dev shell rewrites tests/fixtures/config from
# its `hosts`.
#
# module-config (Linux) builds the config file of each host and each option case with the real
# package, which runs `upstreamer check` on it exactly as a system build does, so the ports the
# module computes and the listeners the compiler derives must agree.
{
  pkgs,
  lib,
  nixpkgs,
  module,
  package,
  # The flake's packages by system, which the module's `package` defaults to.
  packages,
}:
let
  # NixOS hosts are Linux; a Darwin checker evaluates them for aarch64-linux.
  hostPlatform =
    if pkgs.stdenv.hostPlatform.isLinux then pkgs.stdenv.hostPlatform.system else "aarch64-linux";

  files = {
    edge = ./edge.nix;
    apps = ./apps.nix;
    desktop = ./desktop.nix;
    custom = ./custom.nix;
    observed = ./observed.nix;
  };

  eval =
    upstreamer: file:
    (nixpkgs.lib.nixosSystem {
      modules = [
        module
        ./common.nix
        (
          { pkgs, ... }:
          {
            nixpkgs.hostPlatform = hostPlatform;
            services.upstreamer.package = upstreamer pkgs;
          }
        )
        file
      ];
    }).config;

  systems = lib.mapAttrs (_: eval (pkgs: pkgs.writeShellScriptBin "upstreamer" "")) files;

  sorted = lib.sort lib.lessThan;

  observed =
    c:
    let
      u = c.systemd.services.upstreamer;
    in
    {
      failedAssertions = failedAssertions c;
      certs = lib.mapAttrs (_: cert: {
        inherit (cert) domain group;
        extraDomainNames = sorted cert.extraDomainNames;
        reloadServices = sorted cert.reloadServices;
        # The renewal reloads the proxy itself and waits for it, so it fails when the proxy
        # did not take the certificate.
        reloadsProxy = lib.hasInfix "/bin/systemctl try-reload-or-restart upstreamer.service" cert.postRun;
      }) c.security.acme.certs;
      unit = {
        inherit (u.serviceConfig)
          Type
          ExecStart
          ExecReload
          RuntimeDirectory
          RuntimeDirectoryMode
          TimeoutStartSec
          TimeoutStopSec
          ;
        # The program the start path links to, and what a switch to another package or
        # another config does to the unit.
        program = "${c.environment.etc."upstreamer/upstreamer".source}";
        reloadTriggers = sorted (map toString u.reloadTriggers);
        inherit (u) stopIfChanged;
        storesSockets = u.serviceConfig.FileDescriptorStoreMax > 0;
        SupplementaryGroups = sorted u.serviceConfig.SupplementaryGroups;
        wants = sorted u.wants;
      };
      tcp = sorted c.networking.firewall.allowedTCPPorts;
      udp = sorted c.networking.firewall.allowedUDPPorts;
      expectTcp = expectTcpOf c;
      tlsModule = lib.elem "tls" c.boot.kernelModules;
      logs =
        let
          rotate = c.services.logrotate.settings.upstreamer or null;
        in
        {
          directory = u.serviceConfig.LogsDirectory or null;
          readWritePaths = u.serviceConfig.ReadWritePaths or [ ];
          rotated = if rotate == null then [ ] else rotate.files;
          rotation =
            if rotate == null then
              null
            else
              {
                inherit (rotate) frequency compress delaycompress;
                reloads = lib.hasSuffix "/bin/systemctl try-reload-or-restart upstreamer.service" rotate.postrotate;
              };
        };
    };

  # The ports `upstreamer check --expect-tcp` is given when the system builds.
  expectTcpOf =
    c:
    let
      line = lib.findFirst (l: lib.hasInfix "--expect-tcp" l) "" (
        lib.splitString "\n" c.services.upstreamer.configFile.buildCommand
      );
      ports = lib.head (builtins.match ".*--expect-tcp \"([0-9,]*)\".*" line);
    in
    sorted (map lib.toInt (lib.filter (p: p != "") (lib.splitString "," ports)));

  noLogs = {
    directory = null;
    readWritePaths = [ ];
    rotated = [ ];
    rotation = null;
  };

  # `reloadServices` are the other services that read the certificate.
  cert = domain: extraDomainNames: group: reloadServices: {
    inherit
      domain
      extraDomainNames
      group
      reloadServices
      ;
    reloadsProxy = true;
  };
  own = domain: cert domain [ ] "upstreamer-certs" [ ];
  # Every host runs the same package, so the unit differs between hosts only where a field
  # below is derived from the host: `reloadTriggers` holds the host's own config file.
  unit' = timeoutStopSec: groups: certs: host: {
    Type = "notify-reload";
    # A path that stays when the package changes, linked to the package's program.
    ExecStart = "/etc/upstreamer/upstreamer run --config /etc/upstreamer/config.json --reload-socket %t/upstreamer/reload";
    # The command a reload runs: it fails when the reload did. A reload may take as long as
    # a start.
    ExecReload = "/etc/upstreamer/upstreamer reload --reload-socket %t/upstreamer/reload";
    RuntimeDirectory = "upstreamer";
    RuntimeDirectoryMode = "0700";
    TimeoutStartSec = 90;
    program = lib.getExe host.services.upstreamer.package;
    reloadTriggers = sorted [
      "${host.services.upstreamer.configFile}"
      "${host.services.upstreamer.package}"
    ];
    stopIfChanged = false;
    storesSockets = true;
    # The default 10s drain, plus 5s to exit.
    TimeoutStopSec = timeoutStopSec;
    SupplementaryGroups = groups;
    wants = map (c: "acme-${c}.service") certs;
  };
  unit = unit' 15;

  expected = {
    edge = {
      failedAssertions = [ ];
      certs = lib.genAttrs [ "app.example.com" "cache.example.com" "s3.cache.example.com" ] own;
      unit = unit [ "upstreamer-certs" ] [
        "app.example.com"
        "cache.example.com"
        "s3.cache.example.com"
      ] systems.edge;
      tcp = [
        80
        443
      ];
      expectTcp = [
        80
        443
      ];
      udp = [ 443 ];
      tlsModule = true;
      logs = {
        directory = "upstreamer";
        readWritePaths = [ "-/srv/logs" ];
        rotated = [
          "/var/log/upstreamer/access-cache.example.com.log"
          "/srv/logs/s3.log"
        ];
        rotation = {
          frequency = "daily";
          compress = true;
          delaycompress = true;
          reloads = true;
        };
      };
    };
    apps = {
      failedAssertions = [ ];
      certs = lib.genAttrs [ "files.example.net" "play.example.net" "relay.example.net" ] own // {
        "dns.example.net" = cert "dns.example.net" [ ] "dns-certs" [ "dns-server.service" ];
        "mail.example.net" = cert "mail.example.net" [ ] "mail-certs" [ ];
        "example.org" = cert "example.org" [ "blog.example.org" "www.example.org" ] "upstreamer-certs" [ ];
      };
      unit =
        unit
          [ "dns-certs" "mail-certs" "upstreamer-certs" ]
          [
            "dns.example.net"
            "example.org"
            "files.example.net"
            "mail.example.net"
            "play.example.net"
            "relay.example.net"
          ]
          systems.apps;
      tcp = [
        80
        443
      ];
      expectTcp = [
        80
        443
      ];
      udp = [ 443 ];
      tlsModule = true;
      logs = noLogs;
    };
    desktop = {
      failedAssertions = [ ];
      certs = { };
      unit = unit [ ] [ ] systems.desktop;
      tcp = [ ];
      # The host is served on port 80; it keeps the firewall closed.
      expectTcp = [ 80 ];
      udp = [ ];
      tlsModule = false;
      logs = noLogs;
    };
    custom = {
      failedAssertions = [ ];
      certs = {
        "admin.example.com" = own "admin.example.com";
        "preview.example.com" = cert "preview.example.com" [ "*.preview.example.com" ] "upstreamer-certs" [ ];
      };
      # A 30s drain.
      unit = unit' 35 [ "upstreamer-certs" ] [
        "admin.example.com"
        "preview.example.com"
      ] systems.custom;
      tcp = [
        80
        443
        8080
        8443
      ];
      expectTcp = [
        80
        443
        8080
        8443
      ];
      udp = [
        443
        8443
      ];
      tlsModule = true;
      logs = noLogs;
    };
    observed = {
      failedAssertions = [ ];
      certs = {
        "blog.example.com" = own "blog.example.com";
      };
      unit = unit [ "upstreamer-certs" ] [ "blog.example.com" ] systems.observed;
      # The firewall opens the blog; `check` is told about the metrics listener too.
      tcp = [
        80
        443
      ];
      expectTcp = [
        80
        443
        9100
      ];
      udp = [ 443 ];
      tlsModule = true;
      logs = noLogs;
    };
  };

  # Misconfigured hosts, each with the assertion messages it must fail with.
  rejected = {
    cert-group-named-like-the-unit = {
      module.services.upstreamer = {
        acme.group = "upstreamer";
        virtualHosts."a.example.com".proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer: a certificate group is named upstreamer, the name of the unit's dynamic user and group; systemd will not start the unit while a static group has that name."
      ];
    };
    acme-and-files = {
      module.services.upstreamer.virtualHosts."a.example.com" = {
        tls = {
          acmeCert = "a.example.com";
          certFile = "/run/a.crt";
          keyFile = "/run/a.key";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.\"a.example.com\".tls: set one of acme, acmeCert, or both certFile and keyFile."
      ];
    };
    cert-without-key = {
      module.services.upstreamer.virtualHosts."a.example.com" = {
        tls.certFile = "/run/a.crt";
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.\"a.example.com\".tls: set one of acme, acmeCert, or both certFile and keyFile."
      ];
    };
    files-without-tls = {
      module.services.upstreamer.virtualHosts.plain = {
        tls = {
          enable = false;
          certFile = "/run/a.crt";
          keyFile = "/run/a.key";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.plain.tls: acme, acmeCert, certFile and keyFile need tls.enable."
      ];
    };
    acme-without-tls = {
      module.services.upstreamer.virtualHosts.plain = {
        tls = {
          enable = false;
          acmeCert = "example.com";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.plain.tls: acme, acmeCert, certFile and keyFile need tls.enable."
      ];
    };
    unknown-acme-cert = {
      module.services.upstreamer.virtualHosts = {
        "example.com".proxy = "http://127.0.0.1:1";
        "www.example.com" = {
          tls.acmeCert = "exmaple.com";
          proxy = "http://127.0.0.1:1";
        };
      };
      messages = [
        "services.upstreamer: tls.acmeCert \"exmaple.com\" of www.example.com names a certificate for exmaple.com, which no virtual host serves."
      ];
    };
    unnamed-wildcard-cert = {
      module.services.upstreamer.virtualHosts."*.example.com".proxy = "http://127.0.0.1:1";
      messages = [
        "services.upstreamer.virtualHosts.\"*.example.com\".tls.acmeCert: a wildcard host names its certificate, e.g. \"example.com\" for \"*.example.com\"."
      ];
    };
    in-process-acme-and-nixos-acme = {
      module.services.upstreamer.virtualHosts."a.example.com" = {
        tls = {
          acme.email = "ops@example.com";
          acmeCert = "a.example.com";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.\"a.example.com\".tls: set one of acme, acmeCert, or both certFile and keyFile."
      ];
    };
    in-process-acme-and-files = {
      module.services.upstreamer.virtualHosts."a.example.com" = {
        tls = {
          acme.email = "ops@example.com";
          certFile = "/run/a.crt";
          keyFile = "/run/a.key";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.\"a.example.com\".tls: set one of acme, acmeCert, or both certFile and keyFile."
      ];
    };
    in-process-acme-without-tls = {
      module.services.upstreamer.virtualHosts.plain = {
        tls = {
          enable = false;
          acme.email = "ops@example.com";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.plain.tls: acme, acmeCert, certFile and keyFile need tls.enable."
      ];
    };
    host-named-like-the-metrics-site = {
      module.services.upstreamer = {
        metrics.enable = true;
        virtualHosts._metrics = {
          tls.enable = false;
          proxy = "http://127.0.0.1:1";
        };
      };
      messages = [
        "services.upstreamer.virtualHosts: `_metrics` names the site `metrics.enable` adds; give the virtual host another name."
      ];
    };
    kubeconfig-without-kubernetes = {
      module.services.upstreamer.kubernetes.kubeconfig = "/etc/rancher/k3s/upstreamer.yaml";
      messages = [ "services.upstreamer.kubernetes.kubeconfig needs kubernetes.enable." ];
    };
  };

  # The emitted config, as JSON would carry it.
  hosts = lib.mapAttrs (
    _: c:
    builtins.fromJSON (
      builtins.unsafeDiscardStringContext (builtins.toJSON c.services.upstreamer.generatedSettings)
    )
  ) systems;

  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);

  # What the module derives from one option, without a whole host: `get` reads the pieces from
  # the evaluated system, `want` is what the option must give.
  optionCases =
    let
      plain.services.upstreamer.virtualHosts."app.example.com" = {
        tls.enable = false;
        proxy = "http://127.0.0.1:1";
      };
      settings = c: c.services.upstreamer.generatedSettings;
      siteNamed = name: c: lib.findFirst (s: s.name == name) null (settings c).sites;
      unit = c: c.systemd.services.upstreamer.serviceConfig;
      selfIssued = acme: {
        services.upstreamer.virtualHosts."app.example.com" = {
          tls = { inherit acme; };
          proxy = "http://127.0.0.1:1";
        };
      };
      ports = c: {
        tcp = sorted c.networking.firewall.allowedTCPPorts;
        expectTcp = expectTcpOf c;
      };
    in
    {
      metrics-site = {
        module.imports = [
          plain
          { services.upstreamer.metrics.enable = true; }
        ];
        get = c: { site = siteNamed "_metrics" c; } // ports c;
        want = {
          site = {
            name = "_metrics";
            hosts = [ "*" ];
            tls = null;
            listen = [
              "127.0.0.1:9100"
              "[::1]:9100"
            ];
            routes = [
              {
                when.path = "/metrics";
                metrics = { };
              }
            ];
          };
          # `check` is told about the listener; the firewall does not open it.
          tcp = [ 80 ];
          expectTcp = [
            80
            9100
          ];
        };
      };
      metrics-opened = {
        module.imports = [
          plain
          {
            services.upstreamer.metrics = {
              enable = true;
              openFirewall = true;
              path = "/m";
              listen = [
                "100.64.0.7:9100"
                "[fd7a::7]:9101"
              ];
            };
          }
        ];
        get = c: { routes = (siteNamed "_metrics" c).routes; } // ports c;
        want = {
          routes = [
            {
              when.path = "/m";
              metrics = { };
            }
          ];
          tcp = [
            80
            9100
            9101
          ];
          expectTcp = [
            80
            9100
            9101
          ];
        };
      };
      metrics-off = {
        module = plain;
        get = c: { site = siteNamed "_metrics" c; } // ports c;
        want = {
          site = null;
          tcp = [ 80 ];
          expectTcp = [ 80 ];
        };
      };
      kubernetes-credential = {
        module.imports = [
          plain
          {
            services.upstreamer.kubernetes = {
              enable = true;
              kubeconfig = "/etc/rancher/k3s/upstreamer.yaml";
            };
          }
        ];
        get = c: {
          credential = (unit c).LoadCredential;
          environment = (unit c).Environment;
        };
        want = {
          credential = [ "kubeconfig:/etc/rancher/k3s/upstreamer.yaml" ];
          environment = [ "KUBECONFIG=%d/kubeconfig" ];
        };
      };
      kubernetes-in-cluster = {
        module.imports = [
          plain
          { services.upstreamer.kubernetes.enable = true; }
        ];
        get = c: {
          credential = (unit c).LoadCredential;
          environment = (unit c).Environment;
        };
        want = {
          credential = [ ];
          environment = [ ];
        };
      };
      in-process-acme = {
        module = selfIssued { email = "ops@example.com"; };
        get =
          c:
          {
            tls = (siteNamed "app.example.com" c).tls;
            acme = (settings c).acme;
            certs = lib.attrNames c.security.acme.certs;
            wants = c.systemd.services.upstreamer.wants;
            stateDirectory = (unit c).StateDirectory;
            stateDirectoryMode = (unit c).StateDirectoryMode;
            udp = sorted c.networking.firewall.allowedUDPPorts;
          }
          // ports c;
        want = {
          # No NixOS certificate, and nothing to wait for at boot.
          tls = {
            acme = {
              email = "ops@example.com";
              challenge = "http-01";
            };
            redirectHttp = true;
            http3 = true;
          };
          acme.stateDirectory = "/var/lib/upstreamer";
          certs = [ ];
          wants = [ ];
          stateDirectory = "upstreamer";
          stateDirectoryMode = "0700";
          udp = [ 443 ];
          tcp = [
            80
            443
          ];
          expectTcp = [
            80
            443
          ];
        };
      };
      in-process-acme-on-the-https-port = {
        module = {
          services.upstreamer.virtualHosts."app.example.com" = {
            tls.acme = {
              email = "ops@example.com";
              challenge = "tls-alpn-01";
              directory = "https://acme-staging-v02.api.letsencrypt.org/directory";
            };
            listen = [ { port = 8443; } ];
            proxy = "http://127.0.0.1:1";
          };
        };
        get = c: { tls = (siteNamed "app.example.com" c).tls; } // ports c;
        want = {
          tls = {
            acme = {
              email = "ops@example.com";
              challenge = "tls-alpn-01";
              directory = "https://acme-staging-v02.api.letsencrypt.org/directory";
            };
            redirectHttp = false;
            http3 = true;
          };
          # tls-alpn-01 needs no plain HTTP port.
          tcp = [ 8443 ];
          expectTcp = [ 8443 ];
        };
      };
      in-process-acme-http-01-on-another-port = {
        module = {
          services.upstreamer.virtualHosts."app.example.com" = {
            tls.acme.email = "ops@example.com";
            listen = [ { port = 8443; } ];
            proxy = "http://127.0.0.1:1";
          };
        };
        get = ports;
        want = {
          # The CA still reaches the plain HTTP port.
          tcp = [
            80
            8443
          ];
          expectTcp = [
            80
            8443
          ];
        };
      };
      in-process-acme-state-directory = {
        module.imports = [
          (selfIssued { email = "ops@example.com"; })
          { services.upstreamer.acme.stateDirectory = "/var/lib/up/acme"; }
        ];
        get = c: {
          acme = (settings c).acme;
          stateDirectory = (unit c).StateDirectory;
        };
        want = {
          acme.stateDirectory = "/var/lib/up/acme";
          stateDirectory = "up/acme";
        };
      };
      no-state-directory-without-in-process-acme = {
        module = plain;
        get = c: {
          acme = (settings c).acme or null;
          stateDirectory = (unit c).StateDirectory or null;
        };
        want = {
          acme = null;
          stateDirectory = null;
        };
      };
      trusted-proxies = {
        module.imports = [
          plain
          {
            services.upstreamer.trustedProxies = {
              from = [
                "cloudflare"
                "10.0.0.0/8"
              ];
              header = "CF-Connecting-IP";
            };
          }
        ];
        get = c: (settings c).trustedProxies or null;
        want = {
          from = [
            "cloudflare"
            "10.0.0.0/8"
          ];
          header = "CF-Connecting-IP";
        };
      };
      no-trusted-proxies = {
        module = plain;
        get = c: (settings c).trustedProxies or null;
        want = null;
      };
    };

  # The module's default package, evaluated without a package set by the host.
  defaultPackage =
    settings:
    (nixpkgs.lib.nixosSystem {
      modules = [
        module
        ./common.nix
        {
          nixpkgs.hostPlatform = hostPlatform;
          services.upstreamer = settings;
        }
      ];
    }).config.services.upstreamer.package;

  packageProblems =
    lib.optional (
      (defaultPackage { kubernetes.enable = true; }).drvPath != packages.${hostPlatform}.kubernetes.drvPath
    ) "kubernetes.enable does not default package to the flake's kubernetes package"
    ++ lib.optional (
      (defaultPackage { }).drvPath != packages.${hostPlatform}.default.drvPath
    ) "package does not default to the flake's default package";

  problems =
    packageProblems
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: c:
        let
          seen = observed c;
          fixture = ../../tests/fixtures/config + "/${name}.json";
        in
        lib.optional (seen != expected.${name})
          "${name}: derived ${builtins.toJSON seen}\n  expected ${builtins.toJSON expected.${name}}"
        ++
          lib.optional (!builtins.pathExists fixture || hosts.${name} != lib.importJSON fixture)
            "${name}: the emitted config differs from tests/fixtures/config/${name}.json; run `fixtures` in the dev shell"
        ++ lib.optional (builtins.typeOf c.system.build.toplevel.drvPath != "string") "${name}: no system"
      ) systems
    )
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: case:
        let
          seen = case.get (
            eval (pkgs: pkgs.writeShellScriptBin "upstreamer" "") {
              imports = [ case.module ];
              services.upstreamer.enable = true;
            }
          );
        in
        lib.optional (
          seen != case.want
        ) "option ${name}: derived ${builtins.toJSON seen}\n  expected ${builtins.toJSON case.want}"
      ) optionCases
    )
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: case:
        let
          seen = failedAssertions (
            eval (pkgs: pkgs.writeShellScriptBin "upstreamer" "") {
              imports = [ case.module ];
              services.upstreamer.enable = true;
            }
          );
        in
        lib.optional (
          seen != case.messages
        ) "rejected ${name}: failed ${builtins.toJSON seen}\n  expected ${builtins.toJSON case.messages}"
      ) rejected
    );
in
{
  # `hosts` stays readable while the check fails, so `fixtures` can rewrite what it compares.
  module-eval = pkgs.runCommand "module-eval" { passthru = { inherit hosts; }; } (
    if problems == [ ] then
      "touch $out"
    else
      throw ("module-eval:\n" + lib.concatStringsSep "\n" problems)
  );
}
// lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
  module-config = pkgs.linkFarm "module-config" (
    lib.mapAttrsToList (name: file: {
      name = "${name}.json";
      path = (eval (_: package) file).services.upstreamer.configFile;
    }) files
    ++ lib.mapAttrsToList (name: case: {
      name = "option-${name}.json";
      path =
        (eval (_: package) {
          imports = [ case.module ];
          services.upstreamer.enable = true;
        }).services.upstreamer.configFile;
    }) optionCases
  );
}
