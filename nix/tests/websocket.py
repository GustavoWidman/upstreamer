"""Opens a WebSocket to URL, trusting CA, and checks that a text message comes back unchanged."""

import asyncio
import ssl
import sys

import aiohttp

url, ca = sys.argv[1:3]


async def main():
    context = ssl.create_default_context(cafile=ca)
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url, ssl=context) as socket:
            for text in ["ping", "pong"]:
                await socket.send_str(text)
                message = await asyncio.wait_for(socket.receive(), 5)
                assert message.type == aiohttp.WSMsgType.TEXT, message
                assert message.data == text, message.data
    print("echoed")


asyncio.run(main())
