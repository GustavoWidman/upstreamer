# Reverse proxies of every shape, two certificates shared with other services, and a site whose
# hosts share one certificate.
{
  imports = [ ./site-module.nix ];

  # A certificate another service reads too: its group, and that service's reload.
  users.groups.dns-certs = { };
  security.acme.certs."dns.example.net" = {
    group = "dns-certs";
    reloadServices = [ "dns-server.service" ];
  };
  services.upstreamer.virtualHosts."dns.example.net".proxy = {
    to = "https://127.0.0.1:3443";
    tlsSkipVerify = true;
    headers = {
      X-Real-IP = "{remote_host}";
      CF-Connecting-IP = "{remote_host}";
    };
  };

  services.upstreamer.virtualHosts."relay.example.net".proxy = {
    to = "http://127.0.0.1:48822";
    timeouts.tunnelIdle = "1h";
  };

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
    };
    proxy = "http://127.0.0.1:37993";
  };

  services.example-site = {
    enable = true;
    fragments = builtins.path {
      name = "example-site-fragments";
      path = ../../tests/fixtures/site/upstreamer;
    };
    domains = [
      "example.org"
      "www.example.org"
    ];
    blogDomains = [ "blog.example.org" ];
  };
  # Both use the apex's certificate, which then covers their names.
  services.upstreamer.virtualHosts."www.example.org".tls.acmeCert = "example.org";
  services.upstreamer.virtualHosts."blog.example.org".tls.acmeCert = "example.org";
}
