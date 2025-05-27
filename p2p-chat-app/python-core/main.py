import asyncio
from peer import Peer
from transport import Transport

def on_message(peer_id, msg):
    print(f"[Message] From {peer_id} : {msg}")

async def main():
    me = Peer("Alice")
    transport = Transport(me, on_message)
    await transport.start_server()

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())