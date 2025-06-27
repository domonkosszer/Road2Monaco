import socket
import os
import base64
import json
import sys
import threading
import time
import stun
from datetime import datetime
from encryption import EncryptionHandler
from peer import PeerInfo
from message import MessageFormatter
from logger import ChatLogger
from peers import get_peer_salt, save_peer_salt, update_last_seen

class UDPP2PChatClient:
    def __init__(self):
        self.username = input("Enter your username: ")
        self.password = input("Enter shared password: ")
        self.group_id = input("Enter group name: ").strip()
        self.rendezvous = ('127.0.0.1', 55555)
        self.encryption_handler = None
        self.chat_logger = ChatLogger(self.username)
        self.shared_state = {"salt_from_peer": None, "salt_loaded": False}
        self.encryption_handlers = {}
        self.last_seen_peers = {}
        self.peers = []
        self.peer_ids = set()
        self.first_message_sent = set()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 0))
        self.init_nat()

    def init_nat(self):
        try:
            nat_type, ext_ip, ext_port = stun.get_ip_info(source_port=0)
            print(f"[STUN] NAT Type: {nat_type}")
            print(f"[STUN] External IP: {ext_ip}")
            print(f"[STUN] External Port: {ext_port}")
        except OSError as e:
            print(f"[Error] Failed to perform STUN lookup: {e}")
            sys.exit(1)

    def connect_to_rendezvous(self):
        self.sock.sendto(self.group_id.encode(), self.rendezvous)
        while True:
            data, _ = self.sock.recvfrom(1024)
            if data.decode().strip() == 'ready':
                break

    def resolve_peer_id(self, addr):
        for peer in self.peers:
            if addr[0] == peer.ip and addr[1] == peer.sport:
                return f"{peer.ip}:{peer.sport}"
        return None

    def listen(self):
        warned_no_handler = set()
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                if addr == self.rendezvous:
                    decoded = data.decode(errors='ignore').strip()
                    if decoded in ["ready", "punch", "hello"]:
                        continue
                    parts = decoded.split()
                    if len(parts) == 3:
                        ip, sport, dport = parts
                        peer = PeerInfo(ip, int(sport), int(dport))
                        peer_id = f"{peer.ip}:{peer.sport}"
                        if peer_id not in self.peer_ids:
                            self.peer_ids.add(peer_id)
                            self.peers.append(peer)
                            print(f"\nNew peer joined: {peer}\n> ", end='')
                            self.sock.sendto(b'punch', (peer.ip, peer.dport))
                            self.sock.sendto(b'punch', (peer.ip, peer.sport))
                        continue

                peer_id = self.resolve_peer_id(addr)
                if peer_id is None:
                    continue
                self.last_seen_peers[peer_id] = time.time()
                update_last_seen(peer_id, self.group_id)

                try:
                    msg_preview = data[:20].decode(errors='ignore').strip()
                    if msg_preview in ["punch", "hello"]:
                        continue
                except Exception:
                    continue

                try:
                    message = MessageFormatter.parse_message(data)
                except json.JSONDecodeError as e:
                    print(f"\r[Error] Failed to parse message from {addr}: {e}\n> ", end='')
                    continue

                msg_type = message.get("type", "message")

                if "meta" in message and "salt" in message["meta"]:
                    if peer_id not in self.encryption_handlers:
                        imported_salt = base64.b64decode(message["meta"]["salt"])
                        self.encryption_handlers[peer_id] = EncryptionHandler(self.password, imported_salt)
                        save_peer_salt(peer_id, imported_salt, self.group_id)
                        self.shared_state["salt_from_peer"] = imported_salt
                        self.shared_state["salt_loaded"] = True
                        print(f"[System] Imported salt from peer.")

                handler = self.encryption_handlers.get(peer_id)
                if handler is None:
                    if peer_id not in warned_no_handler:
                        print(f"\r[Info] No encryption handler for {peer_id}, waiting for salt...\n> ", end='')
                        warned_no_handler.add(peer_id)
                    continue

                if msg_type == "message":
                    payload = message.get("payload", {})
                    ciphertext = payload.get("text", "")
                    received_hmac = payload.get("hmac", "")

                    if not handler.verify_hmac(ciphertext.encode(), received_hmac):
                        print(f"\r[{message.get('timestamp', '')}] {message.get('name', 'Unknown')}: [Invalid signature]\n> ", end='')
                        continue

                    text = handler.decrypt(payload)
                    formatted = f"[{message.get('timestamp', '')}] {message.get('name', 'Unknown')}: {text}"
                    print(f"\r{formatted}\n> ", end='')
                    self.chat_logger.log(formatted)
                elif msg_type == "ping":
                    pong = json.dumps({
                        "type": "pong",
                        "name": self.username,
                        "timestamp": datetime.utcnow().isoformat()
                    }).encode()
                    self.sock.sendto(pong, addr)
                    continue
                elif msg_type == "pong":
                    self.last_seen_peers[peer_id] = time.time()
                    update_last_seen(peer_id, self.group_id)
                    continue
                else:
                    print(f'\r[Unknown message type: {msg_type}]\n> ', end='')

            except Exception as e:
                print(f'\r[Error] {e}\n> ', end='')

    def monitor_peer(self, timeout=30):
        while True:
            time.sleep(5)
            now = time.time()
            for peer_id, seen in list(self.last_seen_peers.items()):
                if now - seen > timeout:
                    print(f"\n[System] Peer {peer_id} appears to be offline or unreachable.\n> ", end='')
                    del self.last_seen_peers[peer_id]

    def keepalive(self):
        while True:
            try:
                ping_msg = json.dumps({
                    "type": "ping",
                    "name": self.username,
                    "timestamp": datetime.utcnow().isoformat()
                }).encode()
                for peer in self.peers:
                    self.sock.sendto(ping_msg, (peer.ip, peer.sport))
            except Exception as e:
                print(f"\n[System] Keepalive failed: {e}\n> ", end='')
            time.sleep(10)

    def start_threads(self):
        threading.Thread(target=self.listen, daemon=True).start()
        threading.Thread(target=self.monitor_peer, daemon=True).start()
        threading.Thread(target=self.keepalive, daemon=True).start()
        threading.Thread(target=self.wait_for_salt, daemon=True).start()

    def wait_for_salt(self):
        while not self.shared_state["salt_loaded"]:
            time.sleep(0.1)
        print("You can now chat:")

    def send_intro(self):
        salt = os.urandom(16)
        self.encryption_handler = EncryptionHandler(self.password, salt)
        intro_msg = MessageFormatter.create_message(self.username, {"text": "[intro]"}, {
            "salt": base64.b64encode(salt).decode()
        })
        for peer in self.peers:
            for _ in range(3):  # send intro message 3 times
                self.sock.sendto(intro_msg.encode(), (peer.ip, peer.sport))
                time.sleep(0.2)

    def handle_command(self, cmd):
        if cmd == "/help":
            print("\nAvailable commands:\n  /help    Show this help message\n  /quit    Exit the chat\n  /who     Show peer info\n  /reconnect    Attempt to reconnect to peer\n  /lastseen  Show last seen timestamps for known peers\n")
        elif cmd == "/quit":
            print("Quitting...")
            exit(0)
        elif cmd == "/who":
            print("Connected peers:")
            for p in self.peers:
                print(f"  - {p}")
        elif cmd == "/reconnect":
            self.connect_to_rendezvous()
        elif cmd == "/lastseen":
            from peers import load_last_seen
            last_seen_data = load_last_seen()
            if not last_seen_data:
                print("No last seen data available.")
            else:
                print("Last seen timestamps for known peers:")
                for peer_id, timestamp in last_seen_data.items():
                    print(f"  {peer_id}: {timestamp}")
        else:
            print(f"Unknown command: {cmd}\nType /help for available commands.")

    def chat_loop(self):
        print(f"[{self.username}] Waiting for peers in group '{self.group_id}'...")
        while len(self.peers) < 1:
            time.sleep(0.1)

        for peer in self.peers:
            self.sock.sendto(b'punch', (peer.ip, peer.dport))
            self.sock.sendto(b'punch', (peer.ip, peer.sport))

        self.send_intro()

        try:
            while True:
                msg = input("> ").strip()
                if not msg:
                    continue
                if msg.startswith("/"):
                    self.handle_command(msg)
                    continue

                encrypted_payload = self.encryption_handler.encrypt(msg)
                for peer in self.peers:
                    peer_id = f"{peer.ip}:{peer.sport}"
                    if peer_id not in self.first_message_sent:
                        meta = {"salt": base64.b64encode(self.encryption_handler.salt).decode()}
                        message = MessageFormatter.create_message(self.username, encrypted_payload, meta)
                        self.first_message_sent.add(peer_id)
                    else:
                        message = MessageFormatter.create_message(self.username, encrypted_payload)

                    self.sock.sendto(message.encode(), (peer.ip, peer.sport))

        except KeyboardInterrupt:
            print("\n[System] Chat interrupted by user. Exiting.")
            sys.exit(0)

if __name__ == '__main__':
    client = UDPP2PChatClient()
    client.connect_to_rendezvous()
    client.start_threads()
    client.chat_loop()