class ChatLogger:
    """
    Handles writing chat messages to a local text file.
    """

    def __init__(self, username: str):
        """
        Args:
            username (str): Username to create a personalized log file.
        """
        self.filename = f"chat_log_{username}.txt"

    def log(self, msg: str):
        """
        Logs a message to the file with UTF-8 encoding.
        Args:
            msg (str): Message to log.
        """
        with open(self.filename, 'a', encoding='utf-8') as f:
            f.write(msg + '\n')