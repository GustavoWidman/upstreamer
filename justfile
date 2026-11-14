# Benchmark harness (Linux bench host only); see bench/README.md.
bench *args:
    nix run .#bench -- {{ args }}
