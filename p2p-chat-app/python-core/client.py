# UDP P2P Chat Client
# Dieses Skript verbindet sich mit einem Rendezvous-Server, erhält Peer-Informationen,
# führt UDP Hole Punching durch und ermöglicht dann den direkten Chat zwischen zwei Peers.

import socket
import json
import threading
from datetime import datetime

# Benutzername für diesen Peer abfragen
USERNAME = input("Enter your username: ")

# Adresse des Rendezvous-Servers (IP, Port)
RENDEZVOUS = ('127.0.0.1', 55555)

# UDP-Socket erstellen und an einen zufälligen lokalen Port binden
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 0))  # 0 = beliebiger freier Port
my_port = sock.getsockname()[1]

print(f"[{USERNAME}] Using local port: {my_port}")
print(f"[{USERNAME}] Contacting rendezvous server at {RENDEZVOUS}")

# Kontaktaufnahme mit dem Rendezvous-Server
sock.sendto(b'hello', RENDEZVOUS)

# Warten auf Peer-Informationen vom Server
while True:
    data, _ = sock.recvfrom(1024)
    msg = data.decode().strip()

    if msg == 'ready':
        # Server signalisiert, dass der Peer registriert ist, aber noch kein zweiter Peer da ist
        print(f"[{USERNAME}] Waiting for peer to connect...")
        continue

    # Wenn keine 'ready'-Nachricht, dann Peer-Info empfangen
    peer_ip, peer_sport, peer_dport = msg.split()
    peer_sport = int(peer_sport)
    peer_dport = int(peer_dport)
    break

print(f"[{USERNAME}] Connected to peer at {peer_ip}:{peer_sport} (sending) / {peer_dport} (receiving)")

# Listener-Thread für eingehende Nachrichten starten
def listen():
    while True:
        data, _ = sock.recvfrom(1024)
        try:
            decoded = data.decode().strip()
            if not decoded.startswith('{'):
                continue  # Ignore non-JSON messages like "punch"

            message = json.loads(decoded)
            msg_type = message.get("type", "message")

            if msg_type == "message":
                name = message.get("name", "Unknown")
                timestamp = message.get("timestamp", "")
                text = message.get("text", "")
                print(f"\r[{timestamp}] {name}: {text}\n> ", end='')
            else:
                print(f'\r[Unknown message type: {msg_type}] {decoded}\n> ', end='')
        except Exception as e:
            print(f'\r[Error] {e}\n> ', end='')

threading.Thread(target=listen, daemon=True).start()

# UDP Hole Punching: Dummy-Pakete an beide Peer-Ports senden, um NAT zu durchdringen
print(f"[{USERNAME}] Punching hole...")
sock.sendto(b'punch', (peer_ip, peer_dport))
sock.sendto(b'punch', (peer_ip, peer_sport))

# Haupt-Chat-Schleife: Nachrichten eingeben und an den Peer senden
print("[System] You can now chat:")
while True:
    msg = input("> ")
    message = {
        "type": "message",
        "name": USERNAME,
        "timestamp": datetime.utcnow().isoformat(),
        "text": msg
    }
    # Nachricht als JSON an den Peer senden
    sock.sendto(json.dumps(message).encode(), (peer_ip, peer_sport))