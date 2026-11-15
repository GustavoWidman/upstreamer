"""Upstream for the proxy tests: /ws echoes WebSocket text messages, every other path answers
"backend <method> <path>"."""

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
    return web.Response(text=f"backend {request.method} {request.path_qs}")


app = web.Application()
app.router.add_get("/ws", echo)
app.router.add_route("*", "/{tail:.*}", answer)
web.run_app(app, host=sys.argv[1], port=int(sys.argv[2]))
