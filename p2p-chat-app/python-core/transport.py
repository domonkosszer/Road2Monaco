# transport.py
# This module defines the Transport class, responsible for managing peer-to-peer connections
# and transmitting messages between peers in the chat network using asyncio streams.

import asyncio
import json
from typing import Callable, Dict

class Transport:
    """
        Handles network communication between peers using asyncio streams.
        Attributes:
            peer: The local peer instance represents this device/user in the network.
            on_message: A callback function to handle incoming messages (peer_id, message).
            server: The asyncio server instance for accepting incoming connections.
            connections (dict): Maps peer IDs to StreamWriter objects for sending messages.
    """

    def __init__(self, peer, on_message: Callable[[str, str], None]):
        """
            Initializes the Transport instance.
            Args:
                peer: Local peer object containing Id, host and port.
                on_message: Callback function is triggered when a message is received.
        """
        self.peer = peer
        self.on_message = on_message
        self.server = None
        self.connections: Dict[str, asyncio.StreamWriter] = {}

    async def start_server(self):

        """
            Starts the asyncio server to listen for incoming peer connections.
            Updates the peer's port if one was assigned dynamically.
        """
        self.server = await asyncio.start_server(
            self._handle_connection, self.peer.host, self.peer.port
        )
        addr = self.server.sockets[0].getsockname()
        self.peer.port = addr[1] # Save the actual port in case it was assigned automatically
        print(f"[Transport] Listening on {addr}")

    async def _handle_connection(self, reader, writer):
        """
            Handles incoming connections from peers.
            Args:
                reader: StreamReader for reading data from the connection.
                writer: StreamWriter for sending data to the connection.
        """
        peer_id = writer.get_extra_info('peername')[0]
        print(f"[Transport] New connection from {peer_id}")

        while True:
            data = await reader.readline()
            if not data:
                break # Connection closed
            try:
                message = data.decode().strip()
                payload = json.loads(message) # Expecting JSON messages
                sender_id = payload.get("id", "unknown")
                msg = payload.get("msg", "")
                self.on_message(sender_id, msg) # Trigger message handler
            except Exception as e:
                print(f"[Transport] Error processing message from {peer_id}: {e}")

        writer.close()
        await writer.wait_closed()

    async def connect_to_peer(self, host: str, port: int, peer_id: str):
        """
            Initiates a connection to another peer and stores the writer for future messages.

            Args:
                host (str): IP address of the target peer.
                port (int): Port number of the target peer.
                peer_id (str): The unique identifier of the target peer.
        """
        try:
            reader, writer = await asyncio.open_connection(host, port)
            self.connections[peer_id] = writer  # Save writer for future use
            print(f"[Transport] Connected to {peer_id} at {host}:{port}")
        except Exception as e:
            print(f"[Transport] Failed to connect: {e}")

    async def send_message(self, peer_id: str, msg: str):
        """
            Sends a message to a connected peer.

            Args:
                peer_id (str): The ID of the peer to send the message to.
                msg (str): The message content.
        """
        writer = self.connections.get(peer_id)
        if writer:
            payload = json.dumps({
                "id": self.peer.id,
                "msg": msg
            }) + "\n"  # Append newline for readline compatibility
            writer.write(payload.encode())
            await writer.drain()
        else:
            print(f"[Transport] No connection to {peer_id}")