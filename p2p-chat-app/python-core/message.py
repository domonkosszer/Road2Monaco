import json
from datetime import datetime

class MessageFormatter:
    """
    Handles formatting and parsing of chat messages using JSON.
    """

    @staticmethod
    def create_message(username: str, payload: dict, meta: dict = None) -> str:
        """
        Creates a JSON message with optional metadata and signed encrypted payload.
        """
        message = {
            "type": "message",
            "name": username,
            "timestamp": datetime.utcnow().isoformat(),
            "payload": payload
        }
        if meta:
            message["meta"] = meta
        return json.dumps(message)

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