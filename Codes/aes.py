import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class Aes:
    def __init__(self,shared_key=None):
        # La clé partagée peut être passée ici
        self.key = shared_key  # La clé AES est initialisée à partir de la clé partagée
        self.block_size = AES.block_size

    def encrypt(self, msg):
        if not self.key:
            raise ValueError("La clé AES n'est pas définie. Diffie-Hellman échoué.")

        # Générer un IV aléatoire pour chaque chiffrement
        iv = get_random_bytes(self.block_size)

        # Initialiser le chiffreur AES en mode CBC avec la clé et l'IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Ajouter un padding pour que le message soit un multiple de la taille du bloc
        padded_msg = pad(msg.encode(), self.block_size)

        # Chiffrer le message
        encrypted_msg = cipher.encrypt(padded_msg)

        # Retourner l'IV + le message chiffré
        return iv + encrypted_msg

    def decrypt(self, encrypted_msg):
        if not self.key:
            raise ValueError("La clé AES n'est pas définie. Diffie-Hellman échoué.")

        # Extraire l'IV du début du message chiffré
        iv = encrypted_msg[:self.block_size]
        encrypted_data = encrypted_msg[self.block_size:]

        # Initialiser le déchiffreur AES en mode CBC avec la clé et l'IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Déchiffrer les données
        decrypted_msg = cipher.decrypt(encrypted_data)

        # Supprimer le padding
        unpadded_msg = unpad(decrypted_msg, self.block_size)

        # Retourner le message déchiffré
        return unpadded_msg.decode('utf-8')  # Décoder les bytes en string