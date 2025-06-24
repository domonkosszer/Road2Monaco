import json
from datetime import datetime

class MessageFormatter:
    """
    Handles formatting and parsing of chat messages using JSON.
    """

    @staticmethod
    def create_message(username: str, payload: dict) -> str:
        """
        Creates a JSON message with metadata and signed encrypted payload.
        Args:
            username (str): Sender's username.
            payload (dict): Encrypted and signed message body as a dictionary.
        Returns:
            str: JSON-formatted string.
        """
        return json.dumps({
            "type": "message",
            "name": username,
            "timestamp": datetime.utcnow().isoformat(),
            "payload": payload
        })

    @staticmethod
    def parse_message(data: bytes) -> dict:
        """
        Parses received JSON-formatted message data.
        Args:
            data (bytes): Raw byte input from socket.
        Returns:
            dict: Parsed message.
        """
        return json.loads(data.decode().strip())