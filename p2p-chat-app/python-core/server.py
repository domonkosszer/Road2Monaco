# UDP Rendezvous Server
# Dieses Skript implementiert einen einfachen Rendezvous-Server für P2P-Chat.
# Er nimmt Verbindungen von zwei Clients entgegen, tauscht deren Adressen aus
# und ermöglicht so direktes Peer-to-Peer-Messaging (z.B. für UDP Hole Punching).

import socket

known_port = 12345  # Beispielport, der an die Peers kommuniziert wird

# Erstelle UDP-Socket und binde an Port 55555 (Rendezvous-Port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 55555))
print("[Server] Rendezvous server is running on port 55555...")

while True:
    clients = []  # Liste für die Adressen der verbundenen Clients

    # Warte, bis sich zwei Clients gemeldet haben
    while len(clients) < 2:
        data, addr = sock.recvfrom(1024)
        if not data:
            continue
        print(f"[Server] Client connected: {addr}")
        clients.append(addr)
        # Sende 'ready' an den Client, um zu signalisieren, dass er registriert ist
        sock.sendto(b'ready', addr)

    # Wenn zwei Clients verbunden sind, tausche deren Adressen aus
    c1 = clients[0]
    c2 = clients[1]
    # Sende c1s IP und Port an c2, und umgekehrt
    sock.sendto(f"{c1[0]} {c1[1]} {known_port}".encode(), c2)
    sock.sendto(f"{c2[0]} {c2[1]} {known_port}".encode(), c1)
    print(f"[Server] Exchanged info: {c1} <--> {c2}")