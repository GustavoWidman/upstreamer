"""Upstream for the proxy tests: /ws echoes WebSocket text messages, every other path answers
"backend <method> <path>", after as many seconds as a `wait` in its query says."""

import asyncio
import sys

from aiohttp import WSMsgType, web


async def echo(request):
    socket = web.WebSocketResponse()
    await socket.prepare(request)
    async for message in socket:
        if message.type == WSMsgType.TEXT:
            await socket.send_str(message.data)
    return socket


async def answer(request):
    wait = float(request.query.get("wait", 0))
    if wait:
        print(f"holding {request.path} for {wait:g} s", flush=True)
        await asyncio.sleep(wait)
    return web.Response(text=f"backend {request.method} {request.path_qs}")


app = web.Application()
app.router.add_get("/ws", echo)
app.router.add_route("*", "/{tail:.*}", answer)
web.run_app(app, host=sys.argv[1], port=int(sys.argv[2]))
