# UDP P2P Chat Client
# Dieses Skript verbindet sich mit einem Rendezvous-Server, ermittelt den NAT-Typ,
# führt UDP Hole Punching durch und ermöglicht dann den direkten Chat zwischen zwei Peers.
# Erweiterungen: Ende-zu-Ende Verschlüsselung mit Fernet und lokale Chat-Verlaufsprotokollierung

import socket
import json
import threading
import time
import stun
from datetime import datetime
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Benutzername eingeben
USERNAME = input("Enter your username: ")

# Adresse des Rendezvous-Servers
RENDEZVOUS = ('127.0.0.1', 55555)

# Symmetrischer Schlüssel für Fernet-Verschlüsselung (in der Praxis: vorher sicher austauschen)
# Passwort eingeben
password = input("Enter shared password: ").encode()
salt = b'static_salt_12345678'  # In practice, use a unique, shared salt or exchange it securely
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100_000,
    backend=default_backend()
)
FERNET_KEY = base64.urlsafe_b64encode(kdf.derive(password))
fernet = Fernet(FERNET_KEY)
print(f"[System] Share this key securely with your peer to enable decryption: {FERNET_KEY.decode()}")
# print(f"[System] Share this key securely with your peer to enable decryption: {FERNET_KEY.decode()}")
# Lokale Datei zur Protokollierung des Chatverlaufs

chat_log_file = f"chat_log_{USERNAME}.txt"

def log_message(msg):
    with open(chat_log_file, 'a', encoding='utf-8') as f:
        f.write(msg + '\n')

# NAT-Informationen ermitteln
def get_nat_info():
    nat_type, external_ip, external_port = stun.get_ip_info()
    print(f"[STUN] NAT Type: {nat_type}")
    print(f"[STUN] External IP: {external_ip}")
    print(f"[STUN] External Port: {external_port}")
    return nat_type, external_ip, external_port

# UDP-Socket einrichten
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 0))

# Hole NAT-Infos
nat_type, ext_ip, ext_port = get_nat_info()
my_port = sock.getsockname()[1]
print(f"[{USERNAME}] Using local port: {my_port}")
print(f"[{USERNAME}] Contacting rendezvous server at {RENDEZVOUS}")

# Registrierung beim Rendezvous-Server
sock.sendto(b'hello', RENDEZVOUS)

# Peer-Daten empfangen
while True:
    data, _ = sock.recvfrom(1024)
    msg = data.decode().strip()
    if msg == 'ready':
        print(f"[{USERNAME}] Waiting for peer to connect...")
        continue
    peer_ip, peer_sport, peer_dport = msg.split()
    peer_ip = str(peer_ip)
    peer_sport = int(peer_sport)
    peer_dport = int(peer_dport)
    break

print(f"[{USERNAME}] Connected to peer at {peer_ip}:{peer_sport} (sending) / {peer_dport} (receiving)")

# Zeitpunkt der letzten empfangenen Nachricht
last_seen = time.time()

# Nachrichtenempfang
def listen():
    global last_seen
    while True:
        data, _ = sock.recvfrom(1024)
        last_seen = time.time()
        try:
            decoded = data.decode().strip()
            if not decoded.startswith('{'):
                continue
            message = json.loads(decoded)
            msg_type = message.get("type", "message")
            if msg_type == "message":
                name = message.get("name", "Unknown")
                timestamp = message.get("timestamp", "")
                encrypted_text = message.get("text", "")
                try:
                    text = fernet.decrypt(encrypted_text.encode()).decode()
                except Exception:
                    text = "[Encrypted message could not be decrypted]"
                formatted = f"[{timestamp}] {name}: {text}"
                print(f"\r{formatted}\n> ", end='')
                log_message(formatted)
            elif msg_type == "ping":
                continue
            else:
                print(f'\r[Unknown message type: {msg_type}] {decoded}\n> ', end='')
        except Exception as e:
            print(f'\r[Error] {e}\n> ', end='')

# Peer-Verbindung überwachen
def monitor_peer(timeout=30):
    while True:
        time.sleep(5)
        if time.time() - last_seen > timeout:
            print(f"\n[System] Peer appears to be offline or unreachable.\n> ", end='')

# Keepalive-Pings senden
def keepalive():
    while True:
        try:
            ping_msg = json.dumps({
                "type": "ping",
                "name": USERNAME,
                "timestamp": datetime.utcnow().isoformat()
            }).encode()
            sock.sendto(ping_msg, (peer_ip, peer_sport))
        except Exception as e:
            print(f"\n[System] Keepalive failed: {e}\n> ", end='')
        time.sleep(10)

# Hole Punching senden
print(f"[{USERNAME}] Punching hole...")
sock.sendto(b'punch', (peer_ip, peer_dport))
sock.sendto(b'punch', (peer_ip, peer_sport))

# Threads starten
threading.Thread(target=listen, daemon=True).start()
threading.Thread(target=monitor_peer, daemon=True).start()
threading.Thread(target=keepalive, daemon=True).start()

# Eingabe verarbeiten und Befehle erkennen
def handle_command(cmd):
    if cmd == "/help":
        print("\nAvailable commands:\n  /help    Show this help message\n  /quit    Exit the chat\n  /who     Show peer info\n")
    elif cmd == "/quit":
        print("[System] Quitting...")
        exit(0)
    elif cmd == "/who":
        print(f"[System] Peer: {peer_ip}:{peer_sport} (sending) / {peer_dport} (receiving)")
    else:
        print(f"[System] Unknown command: {cmd}\nType /help for available commands.")

# Haupt-Chat-Schleife
print("[System] You can now chat:")
while True:
    msg = input("> ").strip()
    if not msg:
        continue
    if msg.startswith("/"):
        handle_command(msg)
        continue

    try:
        encrypted_text = fernet.encrypt(msg.encode()).decode()
        message = {
            "type": "message",
            "name": USERNAME,
            "timestamp": datetime.utcnow().isoformat(),
            "text": encrypted_text
        }
        sock.sendto(json.dumps(message).encode(), (peer_ip, peer_sport))
    except Exception as e:
        print(f"[Error] Failed to encrypt/send message: {e}")