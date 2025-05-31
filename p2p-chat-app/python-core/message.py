import json
from datetime import datetime

class MessageFormatter:
    """
    Handles formatting and parsing of chat messages using JSON.
    """

    @staticmethod
    def create_message(username: str, encrypted_text: str) -> str:
        """
        Creates a JSON message with metadata.
        Args:
            username (str): Sender's username.
            encrypted_text (str): Encrypted message body.
        Returns:
            str: JSON-formatted string.
        """
        return json.dumps({
            "type": "message",
            "name": username,
            "timestamp": datetime.utcnow().isoformat(),
            "text": encrypted_text
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