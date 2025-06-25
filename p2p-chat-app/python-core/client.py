# UDP P2P Chat Client
# Connects to a Rendezvous Server, performs NAT detection, UDP Hole Punching,
# and enables end-to-end encrypted messaging with local chat logging.

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
from peers import get_peer_salt, save_peer_salt

# Prompt for user input
USERNAME = input("Enter your username: ")
RENDEZVOUS = ('127.0.0.1', 55555)
password = input("Enter shared password: ")
GROUP_ID = input("Enter group name: ").strip()
encryption_handler = None
peer_online = True
shared_state = {
    "salt_from_peer": None,
    "salt_loaded": False
}

encryption_handlers = {}
last_seen_peers = {}

# Initialize components
chat_logger = ChatLogger(USERNAME)
print(f"[System] Share this key securely with your peer to enable decryption.")

# Get NAT information
def get_nat_info():
    try:
        nat_type, external_ip, external_port = stun.get_ip_info(source_port=0)
        print(f"[STUN] NAT Type: {nat_type}")
        print(f"[STUN] External IP: {external_ip}")
        print(f"[STUN] External Port: {external_port}")
        return nat_type, external_ip, external_port
    except OSError as e:
        print(f"[Error] Failed to perform STUN lookup: {e}")
        sys.exit(1)
        return None


# Create and bind socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 0))

# Display local port and contact server
nat_type, ext_ip, ext_port = get_nat_info()
my_port = sock.getsockname()[1]
print(f"[{USERNAME}] Using local port: {my_port}")
print(f"[{USERNAME}] Contacting rendezvous server at {RENDEZVOUS}")


sock.sendto(GROUP_ID.encode(), RENDEZVOUS)
peers = []
peer_ids = set()

# === Neuer Handshake: nur bis zum 'ready'-Ack ===
while True:
    data, _ = sock.recvfrom(1024)
    if data.decode().strip() == 'ready':
        print(f"[{USERNAME}] Server says 'ready' – starting listener threads …")
        break

# Track last received message time
last_seen = time.time()

# Listening thread
def listen():
    global encryption_handlers, last_seen_peers
    global warned_no_handler
    warned_no_handler = set()
    while True:
        try:
            data, addr = sock.recvfrom(4096)

            if addr == RENDEZVOUS:
                decoded = data.decode(errors='ignore').strip()
                # Skip control messages
                if decoded in ["ready", "punch", "hello"]:
                    continue
                parts = decoded.split()
                if len(parts) == 3:
                    ip, sport, dport = parts
                    peer = PeerInfo(ip, int(sport), int(dport))
                    peer_id = f"{peer.ip}:{peer.sport}"
                    if peer_id not in peer_ids:
                        peer_ids.add(peer_id)
                        peers.append(peer)
                        print(f"\n[System] Neuer Peer: {peer}\n> ", end='')
                        # Hole Punching für neuen Peer
                        sock.sendto(b'punch', (peer.ip, peer.dport))
                        sock.sendto(b'punch', (peer.ip, peer.sport))
                    continue

            peer_id = f"{addr[0]}:{addr[1]}"
            last_seen_peers[peer_id] = time.time()

            # Check for non-JSON control messages early
            try:
                msg_preview = data[:20].decode(errors='ignore').strip()
                if msg_preview in ["punch", "hello"]:
                    continue
            except Exception:
                continue  # skip undecodable or malformed control messages

            # Try to parse the full JSON message
            try:
                message = MessageFormatter.parse_message(data)
            except json.JSONDecodeError as e:
                print(f"\r[Error] Failed to parse message from {addr}: {e}\n> ", end='')
                continue

            msg_type = message.get("type", "message")

            # Salt handling
            if "meta" in message and "salt" in message["meta"]:
                imported_salt = base64.b64decode(message["meta"]["salt"])
                encryption_handlers[peer_id] = EncryptionHandler(password, imported_salt)
                save_peer_salt(peer_id, imported_salt)

                shared_state["salt_from_peer"] = imported_salt
                shared_state["salt_loaded"] = True
                print(f"[System] Imported salt from peer.")

            handler = encryption_handlers.get(peer_id)
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
                name = message.get("name", "Unknown")
                timestamp = message.get("timestamp", "")
                formatted = f"[{timestamp}] {name}: {text}"
                print(f"\r{formatted}\n> ", end='')
                chat_logger.log(formatted)

            elif msg_type == "ping":
                continue

            else:
                print(f'\r[Unknown message type: {msg_type}]\n> ', end='')

        except Exception as e:
            print(f'\r[Error] {e}\n> ', end='')

# Peer availability check

def monitor_peer(timeout=30):
    while True:
        time.sleep(5)
        now = time.time()
        for peer_id, seen in list(last_seen_peers.items()):
            if now - seen > timeout:
                print(f"\n[System] Peer {peer_id} appears to be offline or unreachable.\n> ", end='')

# Send periodic keep-alive messages
def keepalive():
    while True:
        try:
            ping_msg = json.dumps({
                "type": "ping",
                "name": USERNAME,
                "timestamp": datetime.utcnow().isoformat()
            }).encode()
            for peer in peers:
                sock.sendto(ping_msg, (peer.ip, peer.sport))
        except Exception as e:
            print(f"\n[System] Keepalive failed: {e}\n> ", end='')
        time.sleep(10)

# Starte Hör-, Monitor- und Keepalive-Threads
threading.Thread(target=listen, daemon=True).start()
threading.Thread(target=monitor_peer, daemon=True).start()
threading.Thread(target=keepalive, daemon=True).start()

# Warte auf mindestens einen Peer, bevor fortgefahren wird
print(f"[{USERNAME}] Waiting for peers in group '{GROUP_ID}'...")
while len(peers) < 1:
    time.sleep(0.1)

# UDP Hole Punching

print(f"[{USERNAME}] Punching hole...")
for peer in peers:
    sock.sendto(b'punch', (peer.ip, peer.dport))
    sock.sendto(b'punch', (peer.ip, peer.sport))

# Generate salt once
salt = os.urandom(16)
encryption_handler = EncryptionHandler(password, salt)
first_message_sent = set()

# Send our salt to each peer explicitly after hole punching
intro_msg = MessageFormatter.create_message(USERNAME, {"text": "[intro]"}, {
    "salt": base64.b64encode(salt).decode()
})
for peer in peers:
    sock.sendto(intro_msg.encode(), (peer.ip, peer.sport))


# Command handling
def handle_command(cmd):
    if cmd == "/help":
        print("\nAvailable commands:\n  /help    Show this help message\n  /quit    Exit the chat\n  /who     Show peer info\n  /reconnect    Attempt to reconnect to peer\n")
    elif cmd == "/quit":
        print("[System] Quitting...")
        exit(0)
    elif cmd == "/who":
        print(f"[System] Connected peers:")
        for p in peers:
            print(f"  - {p}")
    elif cmd == "/reconnect":
        print(f"[System] Re-contacting rendezvous server...")
        try:
            sock.sendto(GROUP_ID.encode(), RENDEZVOUS)

            # Wait for peer info again
            peers.clear()
            peer_ids.clear()
            while True:
                data, _ = sock.recvfrom(1024)
                msg = data.decode().strip()
                if msg == 'ready':
                    print(f"[System] Waiting for peers in group '{GROUP_ID}'...")
                    continue
                try:
                    peer_ip, peer_sport, peer_dport = msg.split()
                    peer = PeerInfo(peer_ip, int(peer_sport), int(peer_dport))
                    peer_id = f"{peer.ip}:{peer.sport}"
                    if peer_id not in peer_ids:
                        peer_ids.add(peer_id)
                        peers.append(peer)
                        print(f"[System] Peer joined: {peer}")
                except:
                    continue

                if len(peers) >= 1:
                    break

            # Re-initiate hole punching
            print(f"[System] Sending punch packets to peers...")
            for peer in peers:
                sock.sendto(b'punch', (peer.ip, peer.dport))
                sock.sendto(b'punch', (peer.ip, peer.sport))

        except Exception as e:
            print(f"[System] Reconnect failed: {e}")
    else:
        print(f"[System] Unknown command: {cmd}\nType /help for available commands.")# Main input loop

print("[System] You can now chat:")
try:
    while True:
        msg = input("> ").strip()
        if not msg:
            continue
        if msg.startswith("/"):
            handle_command(msg)
            continue
        try:
            encrypted_payload = encryption_handler.encrypt(msg)

            for peer in peers:
                peer_id = f"{peer.ip}:{peer.sport}"
                if peer_id not in first_message_sent:
                    meta = {
                        "salt": base64.b64encode(salt).decode()
                    }
                    message = MessageFormatter.create_message(USERNAME, encrypted_payload, meta)
                    first_message_sent.add(peer_id)
                else:
                    message = MessageFormatter.create_message(USERNAME, encrypted_payload)

                sock.sendto(message.encode(), (peer.ip, peer.sport))
                save_peer_salt(peer_id, salt)

        except Exception as e:
            print(f"\n[System] Chat error: {e}")
            sys.exit(1)
except KeyboardInterrupt:
    print("\n[System] Chat interrupted by user. Exiting.")
    sys.exit(0)