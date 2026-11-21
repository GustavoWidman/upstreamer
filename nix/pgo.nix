# The profile for a profile-guided build. The instrumented build serves a short loopback load
# shaped like a fleet host's traffic (HTTP/1.1 cleartext and over TLS, full handshakes, large
# responses and uploads, HTTP/2, HTTP/3, static files) through a local origin, and the counters it
# writes on exit are merged into one profile. It is made from the same source as the build that
# uses it, so it always matches the code it optimises.
#
# Each load is a fixed number of requests, never a duration: how many requests a duration holds
# depends on how busy the build machine is, and so would the profile's weights and with them the
# optimiser's choices. With fixed counts two builds of one source train on the same work, and
# their counters differ only where scheduling does (how often a socket read would block).
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
    ready=
    for _ in $(seq 100); do
      if curl -skf -o /dev/null --resolve localhost:18443:127.0.0.1 https://localhost:18443/bytes/2; then
        ready=1
        break
      fi
      sleep 0.1
    done
    [ -n "$ready" ] || { echo "upstreamer did not answer" >&2; exit 1; }

    # load N ARGS...: N requests from h2load, every one answered 2xx. The counts keep the mix
    # of a few seconds of each load on a build machine: weights close to the hot paths' share
    # of a busy host's work. Every client sends SNI localhost.
    load() {
      n=$1
      shift
      log=$(h2load -t2 -n"$n" "$@")
      echo "$log"
      if ! grep -Eq "^requests: $n total, .* $n succeeded, 0 failed, 0 errored, 0 timeout" <<< "$log" ||
        ! grep -Eq "^status codes: $n 2xx, 0 3xx, 0 4xx, 0 5xx" <<< "$log"; then
        echo "training load failed: h2load -n$n $*" >&2
        exit 1
      fi
    }
    load 200000 -c64 --h1 http://127.0.0.1:18081/bytes/1024
    load 200000 -c64 --h1 --sni=localhost https://127.0.0.1:18443/bytes/1024
    load 12000 -c16 --h1 --sni=localhost -H 'Connection: close' https://127.0.0.1:18443/bytes/1024
    load 5000 -c16 --h1 --sni=localhost https://127.0.0.1:18443/bytes/1048576
    load 4500 -c16 --h1 --sni=localhost -d upload https://127.0.0.1:18443/bytes/2
    load 300000 -c16 -m8 --sni=localhost https://127.0.0.1:18443/bytes/1024
    load 1300000 -c16 -m8 --sni=localhost https://127.0.0.1:18444/small.html
    load 160000 -c16 -m8 --sni=localhost --alpn-list=h3 https://127.0.0.1:18443/bytes/1024

    kill -TERM $proxy
    wait $proxy
    kill $origin
    ${llvm-tools}/lib/rustlib/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/bin/llvm-profdata merge -o $out raw/*.profraw
  ''
