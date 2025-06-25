# UDP Rendezvous Server
# Dieses Skript implementiert einen einfachen Rendezvous-Server für P2P-Chat.
# Er nimmt Verbindungen von zwei Clients entgegen, tauscht deren Adressen aus
# und ermöglicht so direktes Peer-to-Peer-Messaging (z.B. für UDP Hole Punching).

import socket
import signal
import sys
from collections import defaultdict

# Erstelle UDP-Socket und binde an Port 55555 (Rendezvous-Port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 55555))
print("[Server] Rendezvous server is running on port 55555...")

groups = defaultdict(list)
# Graceful shutdown handler
def shutdown_server(signum, frame):
    print("\n[Server] Shutting down gracefully...")
    sock.close()
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, shutdown_server)
signal.signal(signal.SIGTERM, shutdown_server)

try:
    while True:
        data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
        if not data:
            continue
        try:
            group_id = data.decode().strip()
        except Exception as e:
            print(f"[Server] Error decoding data: {e}")
            print(f"[Server] Raw data: {data}")

            continue

        if addr not in groups[group_id]:
            groups[group_id].append(addr)
            print(f"[Server] {addr} joined group '{group_id}'. Current members: {groups[group_id]}")

        # Always acknowledge the peer
        sock.sendto(b'ready', addr)

        # Collect current members again
        members = groups[group_id]

        # Notify the newly joined peer of all others
        for peer in members:
            if peer != addr:
                info = f"{peer[0]} {peer[1]} {peer[1]}"
                sock.sendto(info.encode(), addr)

        # Notify all other peers of the new peer only
        for peer in members:
            if peer != addr:
                info = f"{addr[0]} {addr[1]} {addr[1]}"
                sock.sendto(info.encode(), peer)

except Exception as e:
    print(f"[Server] Error: {e}")
finally:
    print("[Server] Cleaning up socket.")
    sock.close()