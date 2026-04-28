bench-backend:
    cargo run --example bench-backend --release

bench:
    oha http://127.0.0.1:9080 -c 50 -n 50000

e2e:
    cd tests/e2e && behave
