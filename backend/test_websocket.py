import asyncio
import websockets

async def test():
    url = "ws://127.0.0.1:8001/ws/events"

    try:
        async with websockets.connect(url) as ws:
            print("SUCCESS: WebSocket connected!")

            message = await asyncio.wait_for(ws.recv(), timeout=10)
            print("Server response:", message)

    except Exception as e:
        print("CONNECTION FAILED:", repr(e))

asyncio.run(test())
