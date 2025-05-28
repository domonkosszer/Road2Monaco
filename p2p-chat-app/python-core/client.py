import socket
import sys
import threading

# The address of the rendezvous server (usually your own machine or a public server)
rendezvous = ('127.0.0.1', 55555)  # Replace with actual IP if needed

# Create a UDP socket and bind to an available random port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 0))  # OS chooses an available port
my_port = sock.getsockname()[1]

print(f'[Client] Connecting to rendezvous server at {rendezvous[0]}:{rendezvous[1]}')
sock.sendto(b'hello', rendezvous)  # Step 1: Notify the server that we're here

# Step 2: Wait for the 'ready' signal and peer information
while True:
    data, addr = sock.recvfrom(1024)
    msg = data.decode().strip()

    if msg == 'ready':
        print('[Client] Received ready from rendezvous server, waiting for peer...')
        continue

    # Once peer info is received, break the loop
    peer_ip, peer_sport, peer_dport = msg.split()
    peer_sport = int(peer_sport)
    peer_dport = int(peer_dport)
    break

print(f"\n[Client] Peer info received:")
print(f"  IP:            {peer_ip}")
print(f"  Source port:   {peer_sport}")
print(f"  Destination port: {peer_dport}\n")

# Step 3: Perform UDP hole punching by sending a dummy message to peer's port
print(f'[Client] Punching hole to {peer_ip}:{peer_dport}')
sock.sendto(b'punch', (peer_ip, peer_dport))

# Step 4: Start a background thread to listen for incoming messages from the peer
def listen():
    while True:
        data, _ = sock.recvfrom(1024)
        print(f'\rPeer: {data.decode()}\n> ', end='')

threading.Thread(target=listen, daemon=True).start()

# Step 5: Main loop to send messages to the peer
print('[Client] You can now send messages to the peer.\n')
while True:
    msg = input('> ')
    sock.sendto(msg.encode(), (peer_ip, peer_sport))