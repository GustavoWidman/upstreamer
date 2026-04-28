bench-backend:
    cargo run --example bench-backend --release

bench:
    nix run nixpkgs#oha -- http://127.0.0.1:19080 -c 50 -n 50000

bench-compare *args:
    bash bench/compare.sh {{ args }}

e2e:
    cd tests/e2e && behave
