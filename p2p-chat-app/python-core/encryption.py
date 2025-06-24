import json

from cryptography.fernet import Fernet
import base64
import hmac
import hashlib
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
        self.hmac_key = key
        self.password = password
        self.salt = salt

    def encrypt(self, message: str) -> dict:
        ciphertext = self.fernet.encrypt(message.encode())
        sig = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).hexdigest()
        return {
            "text": ciphertext.decode(),
            "hmac": sig
        }
    def decrypt(self, payload: dict) -> str:
        try:
            ciphertext = payload["text"].encode()
            received_sig = payload["hmac"]
            calc_sig = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(received_sig, calc_sig):
                return "[Invalid signature]"
            return self.fernet.decrypt(ciphertext).decode()
        except Exception as e:
            return f"[Decryption or HMAC error: {e}]"

    def verify_hmac(self, message: bytes, received_hmac: str) -> bool:
        calc_hmac = hmac.new(self.hmac_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(calc_hmac, received_hmac)