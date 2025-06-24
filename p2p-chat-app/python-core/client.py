# UDP P2P Chat Client
# Connects to a Rendezvous Server, performs NAT detection, UDP Hole Punching,
# and enables end-to-end encrypted messaging with local chat logging.

import socket
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

# Prompt for user input
USERNAME = input("Enter your username: ")
RENDEZVOUS = ('127.0.0.1', 55555)
password = input("Enter shared password: ")

# Initialize components
encryption_handler = EncryptionHandler(password)
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
    global last_seen
    while True:
        data, _ = sock.recvfrom(1024)
        last_seen = time.time()
        try:
            message = MessageFormatter.parse_message(data)
            msg_type = message.get("type", "message")
            if msg_type == "message":
                payload = message.get("payload", {})
                encrypted_text = payload.get("text", "")
                received_hmac = payload.get("hmac", "")
                if not encryption_handler.verify_hmac(encrypted_text.encode(), received_hmac):
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
    while True:
        time.sleep(5)
        if time.time() - last_seen > timeout:
            print(f"\n[System] Peer appears to be offline or unreachable.\n> ", end='')

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
        print("\nAvailable commands:\n  /help    Show this help message\n  /quit    Exit the chat\n  /who     Show peer info\n")
    elif cmd == "/quit":
        print("[System] Quitting...")
        exit(0)
    elif cmd == "/who":
        print(f"[System] Peer: {peer}")
    else:
        print(f"[System] Unknown command: {cmd}\nType /help for available commands.")

# Main input loop
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
        message = MessageFormatter.create_message(USERNAME, encrypted_payload)
        sock.sendto(message.encode(), (peer.ip, peer.sport))
    except Exception as e:
        print(f"[Error] Failed to encrypt/send message: {e}")