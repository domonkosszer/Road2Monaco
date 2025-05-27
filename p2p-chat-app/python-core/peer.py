# This module defines a Peer class, representing a participant in a peer to peer chat network

import uuid
import socket

class Peer:
    """
    Represents a peer in the P2P network.

    Attributes:
        id(str): Unique identifier of the peer.
        name(str): Name of the peer.
        host(str): Ip adress of the peer (defaults to local IP).
        port(int): Port number where the peer listens (0 means system assigned).
    """
    def __init__(self, name: str, host: str = None, port: int = None):

        self.id = str(uuid.uuid4()) # Generate unique UUID for this peer
        self.name = name
        self.host = host or self._get_local_ip()
        self.port = port or 0 # Default to 0 (OS will choose an available port)

    def __repr__(self):
        return f"<Peer {self.name} ({self.id[:8]}) @ {self.host}:{self.port}>"

    @staticmethod
    def _get_local_ip():
        """
        Attempts to detect the local IP address of the current machine.
        Uses a trick to open a UDP socket to an external IP (without sending data).
        Falls back to 127.0.0.1 (localhost) on failure.

        :return:
            str: Detected local IP address.
        """
        try:
            # Create a dummy socket to fet the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # Google's DNS server (used just to determine route)
            local_ip = s.getsockname()[0] # Get local IP used in that route
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'