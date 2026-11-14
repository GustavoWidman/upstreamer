"""Idle-connection client: opens N TLS keep-alive connections, sends one
request on each, holds them idle, then checks each still answers.

wrk cannot do this: its delay() hook also runs before a connection's first
request, so connections would open and never send anything.

Prints `BENCH_IDLE_READY ...` once every connection has its first response,
and `BENCH_IDLE_RESULT {json}` at the end.
"""

import argparse
import asyncio
import json
import resource
import ssl
import time


async def request(reader, writer, host_header: str, path: str) -> int:
    writer.write(f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n".encode())
    await writer.drain()
    head = await reader.readuntil(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    await reader.readexactly(length)
    return status


async def main(a: argparse.Namespace) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    gate = asyncio.Semaphore(a.concurrency)
    host_header = f"{a.sni}:{a.port}"
    errors: dict[str, int] = {}
    statuses: dict[int, int] = {}

    async def open_one():
        async with gate:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(a.host, a.port, ssl=ctx, server_hostname=a.sni), a.timeout
                )
                status = await asyncio.wait_for(request(reader, writer, host_header, a.path), a.timeout)
            except Exception as e:
                errors[type(e).__name__] = errors.get(type(e).__name__, 0) + 1
                return None
            statuses[status] = statuses.get(status, 0) + 1
            return reader, writer

    start = time.monotonic()
    conns = [c for c in await asyncio.gather(*(open_one() for _ in range(a.connections))) if c]
    open_s = time.monotonic() - start
    print(f"BENCH_IDLE_READY open={len(conns)} seconds={open_s:.2f}", flush=True)
    await asyncio.sleep(a.hold)

    alive = 0

    async def check(c):
        nonlocal alive
        try:
            if await asyncio.wait_for(request(*c, host_header, a.path), a.timeout) == 200:
                alive += 1
        except Exception:
            pass

    await asyncio.gather(*(check(c) for c in conns))
    for _, writer in conns:
        writer.close()
    return {
        "connections": a.connections,
        "opened": len(conns),
        "open_seconds": open_s,
        "statuses": statuses,
        "errors": errors,
        "alive_after_hold": alive,
        "hold_seconds": a.hold,
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--sni", default="localhost")
    p.add_argument("--path", default="/bytes/2")
    p.add_argument("--connections", type=int, default=10_000)
    p.add_argument("--concurrency", type=int, default=256, help="handshakes in flight at once")
    p.add_argument("--hold", type=float, default=10)
    p.add_argument("--timeout", type=float, default=30)
    a = p.parse_args()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, a.connections + 4096), hard))
    print("BENCH_IDLE_RESULT " + json.dumps(asyncio.run(main(a))), flush=True)
