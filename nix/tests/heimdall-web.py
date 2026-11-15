"""Writes a web build shaped like heimdall's into OUT: an index page and a few text files, each
with a quality-11 `.br` and a level-9 `.gz` copy, and outside `_app/immutable/` a `.etag`
sidecar holding a quoted 24-character content hash for every file, compressed copies included."""

import base64
import gzip
import hashlib
import pathlib
import sys

import brotli

out = pathlib.Path(sys.argv[1])
sources = {
    "index.html": "<!doctype html><html><head><title>heimdall</title></head><body>app</body></html>\n",
    "manifest.webmanifest": '{"name": "heimdall"}\n',
    "_app/version.json": '{"version": "1"}\n',
    "_app/immutable/entry/start.Bx9e0f.js": "export const start = () => 'heimdall';\n",
}

for name, text in sources.items():
    path = out / name
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode()
    path.write_bytes(data)
    pathlib.Path(f"{path}.br").write_bytes(brotli.compress(data, quality=11))
    pathlib.Path(f"{path}.gz").write_bytes(gzip.compress(data, compresslevel=9, mtime=0))

immutable = out / "_app" / "immutable"
for path in sorted(p for p in out.rglob("*") if p.is_file()):
    if immutable in path.parents:
        continue
    digest = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).decode()
    pathlib.Path(f"{path}.etag").write_text(f'"{digest[:24]}"')
