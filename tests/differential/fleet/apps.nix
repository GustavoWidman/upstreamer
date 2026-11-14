# The fleet host that runs the portfolio, DNS-over-HTTPS, the DERP relay, the game panel, the
# file share, webmail and the tailnet admin. Each block names the Caddy site it replaces in
# ../caddy/apps.Caddyfile.
{
  imports = [ ./portfolio-module.nix ];

  services.portfolio = {
    enable = true;
    package = {
      type = "derivation";
      name = "portfolio";
      outPath = "@portfolio@";
    };
    domains = [
      "example.org"
      "www.example.org"
    ];
    blogDomains = [ "blog.example.org" ];
  };
  services.upstreamer.virtualHosts."www.example.org".tls.acmeCert = "example.org";
  services.upstreamer.virtualHosts."blog.example.org".tls.acmeCert = "example.org";

  # An https upstream with skip-verify and extra header_up fields; Host, X-Forwarded-For and
  # X-Forwarded-Proto are the proxy's defaults.
  users.groups.dns-certs = { };
  security.acme.certs."dns.example.net".group = "dns-certs";
  services.upstreamer.virtualHosts."dns.example.net".proxy = {
    to = "https://127.0.0.1:3443";
    tlsSkipVerify = true;
    headers = {
      X-Real-IP = "{remote_host}";
      X-Original-IP = "{remote_host}";
      CF-Connecting-IP = "{remote_host}";
    };
  };

  # The same header_up fields over plain HTTP.
  services.upstreamer.virtualHosts."admin.example.net".proxy = {
    to = "http://127.0.0.1:59553";
    headers = {
      X-Real-IP = "{remote_host}";
      X-Original-IP = "{remote_host}";
      CF-Connecting-IP = "{remote_host}";
    };
  };

  # `flush_interval -1` and 3600s read and write timeouts on the DERP upgrade.
  services.upstreamer.virtualHosts."relay.example.net".proxy = {
    to = "http://127.0.0.1:48822";
    timeouts.tunnelIdle = "1h";
  };

  # `handle_path /daemon/*` to the daemon, everything else to the panel.
  services.upstreamer.virtualHosts."play.example.net".routes = [
    {
      when.path = "/daemon/*";
      routes = [
        { stripPrefix = "/daemon"; }
        { proxy = "http://127.0.0.1:52930"; }
      ];
    }
    { proxy = "http://127.0.0.1:27613"; }
  ];

  services.upstreamer.virtualHosts."files.example.net".proxy = "http://127.0.0.1:46971";

  users.groups.mail-certs = { };
  security.acme.certs."mail.example.net".group = "mail-certs";
  services.upstreamer.virtualHosts."mail.example.net" = {
    headers = {
      X-Content-Type-Options = "nosniff";
      X-Frame-Options = "SAMEORIGIN";
      Referrer-Policy = "same-origin";
    };
    proxy = "http://127.0.0.1:37993";
  };
}
