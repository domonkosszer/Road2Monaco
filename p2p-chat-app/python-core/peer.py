class PeerInfo:
    """
    Stores and formats information about the peer's IP and port.
    """

    def __init__(self, ip: str, sport: int, dport: int):
        """
        Args:
            ip (str): IP address of the peer.
            sport (int): Port for sending messages.
            dport (int): Port for receiving messages.
        """
        self.ip = ip
        self.sport = sport
        self.dport = dport

    def __str__(self):
        """
        Returns:
            str: Human-readable string of the peer's IP and ports.
        """
        return f"{self.ip}:{self.sport} (sending) / {self.dport} (receiving)"