import socket
import signal
import sys
from collections import defaultdict

class UDPRendezvousServer:
    def __init__(self, host='0.0.0.0', port=55555):
        self.host = host
        self.port = port
        self.groups = defaultdict(list)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True

    def start(self):
        self.sock.bind((self.host, self.port))
        print(f"[Server] Rendezvous server is running on port {self.port}...")

        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

        try:
            while self.running:
                self.handle_client()
        except Exception as e:
            print(f"[Server] Error: {e}")
        finally:
            self.cleanup()

    def handle_client(self):
        data, addr = self.sock.recvfrom(1024)
        if not data:
            return

        try:
            group_id = data.decode().strip()
        except Exception as e:
            print(f"[Server] Error decoding data: {e}")
            print(f"[Server] Raw data: {data}")
            return

        if addr not in self.groups[group_id]:
            self.groups[group_id].append(addr)
            print(f"[Server] {addr} joined group '{group_id}'. Current members: {self.groups[group_id]}")

        self.sock.sendto(b'ready', addr)

        members = self.groups[group_id]
        for peer in members:
            if peer != addr:
                info = f"{peer[0]} {peer[1]} {peer[1]}"
                self.sock.sendto(info.encode(), addr)

        for peer in members:
            if peer != addr:
                info = f"{addr[0]} {addr[1]} {addr[1]}"
                self.sock.sendto(info.encode(), peer)

    def shutdown_handler(self, signum, frame):
        print("\n[Server] Shutting down gracefully...")
        self.running = False

    def cleanup(self):
        print("[Server] Cleaning up socket.")
        self.sock.close()


if __name__ == '__main__':
    server = UDPRendezvousServer()
    server.start()
