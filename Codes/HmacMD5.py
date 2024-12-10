import hmac
from hashlib import md5


class HmacMd5:
    def __init__(self, key):
        self.key = key.encode()  # Convertir la clé en bytes
        self.block_size = 64  # Taille du bloc pour MD5

    def generate_hmac(self, message):
        """Génère le HMAC pour un message donné."""
        return hmac.new(self.key, message.encode(), md5).hexdigest()

    def verify_hmac(self, message, hmac_value):
        """Vérifie si le HMAC du message correspond à celui fourni."""
        return hmac.new(self.key, message.encode(), md5).hexdigest() == hmac_value
