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
encryption_handler = None
peer_online = True
shared_state = {
    "salt_from_peer": None,
    "salt_loaded": False
}

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
sock.sendto(b'hello', RENDEZVOUS)

# Wait for peer data
while True:
    data, _ = sock.recvfrom(1024)
    msg = data.decode().strip()
    if msg == 'ready':
        print(f"[{USERNAME}] Waiting for peer to connect...")
        continue
    peer_ip, peer_sport, peer_dport = msg.split()
    peer = PeerInfo(peer_ip, int(peer_sport), int(peer_dport))
    break

print(f"[{USERNAME}] Connected to peer at {peer}")

# Track last received message time
last_seen = time.time()

# Listening thread
def listen():
    global last_seen, encryption_handler
    while True:
        data, _ = sock.recvfrom(1024)
        last_seen = time.time()

        try:
            decoded = data.decode().strip()

            # Skip non-JSON messages like 'punch'
            if decoded in ["punch", "hello"]:
                continue

            message = MessageFormatter.parse_message(data)
            msg_type = message.get("type", "message")

            # Salt handling...
            if "meta" in message and "salt" in message["meta"]:
                imported_salt = base64.b64decode(message["meta"]["salt"])
                encryption_handler = EncryptionHandler(password, imported_salt)
                save_peer_salt(f"{peer.ip}:{peer.sport}", imported_salt)

                shared_state["salt_from_peer"] = imported_salt
                shared_state["salt_loaded"] = True
                print(f"[System] Imported salt from peer.")

            # Skip until encryption is ready
            if encryption_handler is None:
                print(f"\r[Warning] Message received before key was initialized.\n> ", end='')
                continue

            if msg_type == "message":
                payload = message.get("payload", {})
                ciphertext = payload.get("text", "")
                received_hmac = payload.get("hmac", "")

                if not encryption_handler.verify_hmac(ciphertext.encode(), received_hmac):
                    print(f"\r[{message.get('timestamp', '')}] {message.get('name', 'Unknown')}: [Invalid signature]\n> ", end='')
                    continue

                text = encryption_handler.decrypt(payload)
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
    global peer_online
    while True:
        time.sleep(5)
        if time.time() - last_seen > timeout:
            if peer_online:
                print(f"\n[System] Peer appears to be offline or unreachable.\n> ", end='')
                peer_online = False
        else:
            peer_online = True

# Send periodic keep-alive messages
def keepalive():
    while True:
        try:
            ping_msg = json.dumps({
                "type": "ping",
                "name": USERNAME,
                "timestamp": datetime.utcnow().isoformat()
            }).encode()
            sock.sendto(ping_msg, (peer.ip, peer.sport))
        except Exception as e:
            print(f"\n[System] Keepalive failed: {e}\n> ", end='')
        time.sleep(10)

# UDP Hole Punching
print(f"[{USERNAME}] Punching hole...")
sock.sendto(b'punch', (peer.ip, peer.dport))
sock.sendto(b'punch', (peer.ip, peer.sport))

# Start threads
threading.Thread(target=listen, daemon=True).start()
threading.Thread(target=monitor_peer, daemon=True).start()
threading.Thread(target=keepalive, daemon=True).start()

# Command handling
def handle_command(cmd):
    if cmd == "/help":
        print("\nAvailable commands:\n  /help    Show this help message\n  /quit    Exit the chat\n  /who     Show peer info\n  /reconnect    Attempt to reconnect to peer\n")
    elif cmd == "/quit":
        print("[System] Quitting...")
        exit(0)
    elif cmd == "/who":
        print(f"[System] Peer: {peer}")
    elif cmd == "/reconnect":
        print(f"[System] Re-contacting rendezvous server...")
        try:
            sock.sendto(b'hello', RENDEZVOUS)

            # Wait for peer info again
            while True:
                data, _ = sock.recvfrom(1024)
                msg = data.decode().strip()
                if msg == 'ready':
                    print(f"[System] Waiting for peer to connect...")
                    continue
                peer_ip, peer_sport, peer_dport = msg.split()
                peer.ip = peer_ip
                peer.sport = int(peer_sport)
                peer.dport = int(peer_dport)
                print(f"[System] Reconnected to peer at {peer}")
                break

            # Re-initiate hole punching
            print(f"[System] Sending punch packets to {peer}...")
            sock.sendto(b'punch', (peer.ip, peer.dport))
            sock.sendto(b'punch', (peer.ip, peer.sport))

            peer_id = f"{peer.ip}:{peer.sport}"

        except Exception as e:
            print(f"[System] Reconnect failed: {e}")
    else:
        print(f"[System] Unknown command: {cmd}\nType /help for available commands.")# Main input loop

# Generate salt once
salt = None
peer_id = f"{peer.ip}:{peer.sport}"
for _ in range(20):
    if shared_state["salt_from_peer"]:
        break
    time.sleep(0.1)

saved_salt = shared_state["salt_from_peer"] or get_peer_salt(peer_id)
first_message = False
if saved_salt:
    salt = saved_salt
    encryption_handler = EncryptionHandler(password, saved_salt)
    print(f"[System] Loaded known salt for {peer_id}")
else:
    salt = os.urandom(16)
    encryption_handler = EncryptionHandler(password, salt)
    first_message = True  # we must embed salt in the first message

print("[System] You can now chat:")
while True:
    msg = input("> ").strip()
    if not msg:
        continue
    if msg.startswith("/"):
        handle_command(msg)
        continue
    try:
        encrypted_payload = encryption_handler.encrypt(msg)

        # Wenn Peer-Salt noch nicht bestätigt ist, sende Salt weiterhin mit
        if not shared_state["salt_loaded"]:
            meta = {
                "salt": base64.b64encode(salt).decode()
            }
            message = MessageFormatter.create_message(USERNAME, encrypted_payload, meta)
        else:
            message = MessageFormatter.create_mes<sage(USERNAME, encrypted_payload)

        sock.sendto(message.encode(), (peer.ip, peer.sport))
        save_peer_salt(peer_id, salt)

    except Exception as e:
        print(f"\n[System] Chat error: {e}")
        sys.exit(1)