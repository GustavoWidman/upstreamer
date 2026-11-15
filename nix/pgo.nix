# The profile for a profile-guided build. The instrumented build serves a short loopback load
# shaped like a fleet host's traffic (HTTP/1.1 cleartext and over TLS, full handshakes, large
# responses and uploads, HTTP/2, HTTP/3, static files) through a local origin, and the counters it
# writes on exit are merged into one profile. It is made from the same source as the build that
# uses it, so it always matches the code it optimises; the counts vary a little from build to
# build, so the optimised binary is not bit-for-bit reproducible.
{
  pkgs,
  craneLib,
  llvm-tools,
  instrumented,
}:
let
  origin = craneLib.buildPackage {
    pname = "bench-origin";
    version = "0.1.0";
    src = craneLib.cleanCargoSource ../bench/origin;
    strictDeps = true;
    doCheck = false;
  };
  h2load = pkgs.nghttp2.override { enableHttp3 = true; };
in
pkgs.runCommand "upstreamer.profdata"
  {
    nativeBuildInputs = [
      instrumented
      origin
      h2load
      pkgs.wrk
      pkgs.curl
    ];
  }
  ''
    set -euo pipefail
    export LLVM_PROFILE_FILE=$PWD/raw/%m_%p.profraw
    mkdir raw www
    head -c 1024 /dev/zero | tr '\0' a > www/small.html
    head -c 1048576 /dev/zero > upload

    # Certificate paths that do not exist: the TLS sites serve a self-signed certificate.
    tls='"cert": "missing.pem", "key": "missing.key", "redirectHttp": false'
    cat > upstreamer.json <<EOF
    {
      "version": 1,
      "workers": 2,
      "sites": [
        { "name": "h1", "hosts": ["*"], "listen": ["127.0.0.1:18081"],
          "routes": [{ "proxy": "http://127.0.0.1:18080" }] },
        { "name": "tls", "hosts": ["localhost", "*"], "listen": ["127.0.0.1:18443"],
          "routes": [{ "proxy": "http://127.0.0.1:18080" }], "tls": { $tls, "http3": true } },
        { "name": "static", "hosts": ["localhost", "*"], "listen": ["127.0.0.1:18444"],
          "routes": [{ "files": { "root": "$PWD/www" } }], "tls": { $tls, "http3": false } }
      ]
    }
    EOF

    bench-origin --listen 127.0.0.1:18080 --threads 2 &
    origin=$!
    upstreamer run --config upstreamer.json &
    proxy=$!
    # Clients send SNI localhost: wrk takes it from the URL (and falls back from ::1 to
    # 127.0.0.1), h2load from --sni.
    ready=
    for _ in $(seq 100); do
      if curl -skf -o /dev/null --resolve localhost:18443:127.0.0.1 https://localhost:18443/bytes/2; then
        ready=1
        break
      fi
      sleep 0.1
    done
    [ -n "$ready" ] || { echo "upstreamer did not answer" >&2; exit 1; }

    load_wrk() {
      log=$(wrk -t2 -d3s "$@")
      echo "$log"
      if grep -q 'Non-2xx\|Socket errors' <<< "$log"; then
        echo "training load failed: wrk $*" >&2
        exit 1
      fi
    }
    load_h2load() {
      log=$(h2load -t2 -D3 "$@")
      echo "$log"
      if ! grep -Eq 'status codes: [1-9][0-9]* 2xx, 0 3xx, 0 4xx, 0 5xx' <<< "$log"; then
        echo "training load failed: h2load $*" >&2
        exit 1
      fi
    }
    load_wrk -c64 http://127.0.0.1:18081/bytes/1024
    load_wrk -c64 https://localhost:18443/bytes/1024
    load_wrk -c16 -H 'Connection: close' https://localhost:18443/bytes/1024
    load_wrk -c16 https://localhost:18443/bytes/1048576
    load_h2load -c16 --h1 --sni=localhost -d upload https://127.0.0.1:18443/bytes/2
    load_h2load -c16 -m8 --sni=localhost https://127.0.0.1:18443/bytes/1024
    load_h2load -c16 -m8 --sni=localhost https://127.0.0.1:18444/small.html
    load_h2load -c16 -m8 --sni=localhost --alpn-list=h3 https://127.0.0.1:18443/bytes/1024

    kill -TERM $proxy
    wait $proxy
    kill $origin
    ${llvm-tools}/lib/rustlib/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/bin/llvm-profdata merge -o $out raw/*.profraw
  ''
