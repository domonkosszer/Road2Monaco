from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class EncryptionHandler:
    """
    Handles symmetric Fernet encryption using a password-derived key.
    """

    def __init__(self, password: str, salt: bytes = b'static_salt_12345678'):
        """
        Initializes the Fernet key from a password and salt.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(key)

    def encrypt(self, message: str) -> str:
        """
        Encrypts a message using Fernet.
        Returns:
            str: Encrypted and base64-encoded message.
        """
        return self.fernet.encrypt(message.encode()).decode()

    def decrypt(self, token: str) -> str:
        """
        Decrypts a base64-encoded message.
        Returns:
            str: Decrypted plain text, or fallback message on failure.
        """
        try:
            return self.fernet.decrypt(token.encode()).decode()
        except Exception:
            return "[Encrypted message could not be decrypted]"