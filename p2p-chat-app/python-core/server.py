import socket

# The port that both peers will use to communicate after rendezvous
known_port = 12345

# Create a UDP socket and bind it to port 55555 (acts as the rendezvous server)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 55555))  # Listen on all interfaces

print("[Server] Rendezvous server is running on port 55555...")

while True:
    clients = []

    # Wait until two clients have connected
    while True:
        # Receive a message from a client
        data, addr = sock.recvfrom(1024)
        if not data:
            break  # Ignore empty data

        print(f"[Server] Connection from: {addr}")
        clients.append(addr)

        # Acknowledge the client to let it know it is registered
        sock.sendto(b'ready', addr)

        # Once two clients are connected, proceed to pair them
        if len(clients) == 2:
            print('[Server] Two clients connected, exchanging info...')
            break

    # Pop the two clients from the list
    c1 = clients.pop()
    c1_addr, c1_port = c1  # Client 1's IP and source port

    c2 = clients.pop()
    c2_addr, c2_port = c2  # Client 2's IP and source port

    # Send Client 2's info to Client 1
    # Format: "<IP> <source_port> <known_port>"
    sock.sendto(f'{c1_addr} {c1_port} {known_port}'.encode(), c2)

    # Send Client 1's info to Client 2
    sock.sendto(f'{c2_addr} {c2_port} {known_port}'.encode(), c1)

    print(f"[Server] Sent peer info to both clients:\n"
          f"  Client 1 -> {c1_addr}:{c1_port}\n"
          f"  Client 2 -> {c2_addr}:{c2_port}\n")

