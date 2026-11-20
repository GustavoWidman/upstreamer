# Certificates from ACME, in process

A TLS site can get its certificate from an ACME certificate authority (Let's Encrypt by
default) without any other program. upstreamer creates the account, proves control of the
site's names, stores the certificate and renews it. Only the site's `tls` changes:

```json
{
  "version": 1,
  "sites": [
    {
      "name": "app",
      "hosts": ["example.com", "www.example.com"],
      "tls": { "acme": { "email": "ops@example.com" } },
      "routes": [{ "proxy": { "to": "http://127.0.0.1:8080" } }]
    }
  ]
}
```

In TOML, the same keys:

```toml
[[sites]]
name = "app"
hosts = ["example.com", "www.example.com"]
tls.acme.email = "ops@example.com"
```

On NixOS, prefer the module's `tls.acmeCert`, which uses the system's `security.acme`. A
certificate comes from one of the two, never both.

## Settings

`tls.acme` on a site:

| key | default | |
|---|---|---|
| `email` | required | The account's contact address. |
| `directory` | `https://acme-v02.api.letsencrypt.org/directory` | The CA's directory URL. Let's Encrypt's staging CA is `https://acme-staging-v02.api.letsencrypt.org/directory`. |
| `challenge` | `"http-01"` | How the CA checks that you control the names: `"http-01"` or `"tls-alpn-01"`. |

`acme` at the top level, shared by every such site:

| key | default | |
|---|---|---|
| `stateDirectory` | `/var/lib/upstreamer` | Where account keys and certificates are kept. An absolute path the process can write. |

Asking for a certificate agrees to the CA's terms of service.

## Choosing the challenge

The CA connects to each name on the standard ports, so the names must resolve to this host
and the ports must reach upstreamer.

- `http-01`: the CA fetches `http://<name>/.well-known/acme-challenge/<token>` on port 80.
  The proxy answers it on the `listen.http` addresses before routing: in the site's
  HTTP->HTTPS redirect, or, for a site with its own `listen` or `redirectHttp = false`, on a
  listener that answers the tokens of the site's names and 404 to anything else. This works
  behind anything that forwards port 80.
- `tls-alpn-01`: the CA opens a TLS connection to port 443 asking only for the `acme-tls/1`
  protocol (RFC 8737). Use it when port 80 is closed. It needs the TLS connection to end at
  upstreamer, so it does not work behind a proxy that terminates TLS, such as Cloudflare with
  its proxy on.

Neither can prove a wildcard name (`*.example.com`) or an IP address: `check` rejects both. A
wildcard needs DNS-01, which in-process ACME does not do; use NixOS ACME or certificate files.

## What happens at run time

- Until the first certificate is issued, the site serves a self-signed certificate for its
  names, as a site whose certificate files are missing does. Other sites are not affected.
- Each site's certificate covers all of its `hosts`. Sites with the same hosts and settings
  share one certificate.
- A certificate is renewed when two thirds of its lifetime are over (about 60 days into a
  90-day certificate), less a random part of a thirtieth of it so that certificates issued
  together do not renew together. A certificate whose names no longer match the site's hosts
  is replaced at once.
- A new certificate is served from the next TLS handshake. Connections that are open keep
  theirs. Nothing restarts or reloads.
- A failed order is logged with the CA's reason and retried after a minute, then two, four,
  and so on up to six hours, or later when the CA asks for that (up to a day). The last
  issued certificate stays in use meanwhile.
- After a restart, the stored certificate is served from the first handshake; nothing is
  ordered again unless it is due.

## The state directory

```
<stateDirectory>/acme/<CA>/accounts/<email>.pem              account key
<stateDirectory>/acme/<CA>/certificates/<first host>/fullchain.pem
<stateDirectory>/acme/<CA>/certificates/<first host>/key.pem
```

`<CA>` is the directory URL's host and path (`acme-v02.api.letsencrypt.org_directory`), so
switching between staging and production never overwrites the other's files. Keys are
P-256. Every file is written with mode 0600 in directories with mode 0700, and replaced with
a rename, so a reader never sees half a file. Back up the directory to keep the account; a
lost account key only means a new account on the next order.

On NixOS with the module, give the unit a writable state directory:
`systemd.services.upstreamer.serviceConfig.StateDirectory = "upstreamer";`.

## A private CA

The client verifies the CA's HTTPS certificate against the system trust store
(`SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, then `/etc/ssl/certs/ca-certificates.crt` and
`/etc/ssl/cert.pem`). For a CA such as step-ca or pebble, add its root to that store, or point
`SSL_CERT_FILE` at a bundle that holds it.

## Not supported

DNS-01 and wildcard certificates, IP address certificates, external account binding
(needed by some commercial CAs), ACME renewal information (RFC 9773), and revocation.
