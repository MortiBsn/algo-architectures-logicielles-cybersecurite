import random
import socket
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

import des
from HmacMD5 import HmacMd5
from aes import Aes
class Client ():
    def __init__(self, mode):
        self.mode = mode
        self.sclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.txt = ""

    def connect(self):
        self.sclient.connect(('127.0.0.1',12345))
        print(f"Serveur @IP = {self.sclient.getpeername()[0]}")
        print(f"Port = {self.sclient.getpeername()[1]}")
        print(f"Port used = {self.sclient.getsockname()[1]}")

    def send_data(self):
        self.txt = self.mode.encrypt(self.txt)
        self.sclient.send(self.txt)
        self.sclient.close()
        print("Done with communication")

    def send_data_aes(self):
        # Paramètres Diffie-Hellman
        p = 23  # Nombre premier (petit ici mais normalement plus grand)
        g = 5  # Generateur
        private_key = random.randint(1, p - 1)
        public_key = pow(g, private_key, p)

        # Envoi de la clé publique du client au serveur
        self.sclient.send(str(public_key).encode())

        # Réception de la clé publique du serveur
        server_public_key = int(self.sclient.recv(1024).decode())

        # Calcul de la clé partagée
        shared_key = pow(server_public_key, private_key, p)
        print(f"Clé partagée calculée : {shared_key}")

        # Créer un objet AES avec la clé partagée
        aes = Aes(shared_key.to_bytes(16, byteorder='big'))  # Convertir la clé partagée en bytes

        # Chiffrement du message
        self.txt = aes.encrypt(self.txt)  # Chiffrement du message
        self.sclient.send(self.txt)

        self.sclient.close()
        print("Communication terminée.")

    def send_data_HmacMd5(self,hmac_key):
        hmac_auth = HmacMd5(hmac_key)
        hmac_value = hmac_auth.generate_hmac(self.txt)
        self.sclient.sendall(self.txt.encode())
        self.sclient.sendall(hmac_value.encode())
        print("Message envoyé:", self.txt)
        print("HMAC envoyé:", hmac_value)
        self.sclient.close()

    def receive_data_sha_rsa(self):
        # Réception de la taille de chaque partie
        public_pem_size = struct.unpack("I", self.sclient.recv(4))[0]
        message_size = struct.unpack("I", self.sclient.recv(4))[0]
        signature_size = struct.unpack("I", self.sclient.recv(4))[0]

        # Réception des données
        public_pem = self.sclient.recv(public_pem_size)
        message = self.sclient.recv(message_size)
        signature = self.sclient.recv(signature_size)

        self.sclient.close()
        # Charger la clé publique à partir du PEM
        public_key = load_pem_public_key(public_pem)

        # Vérification de la signature avec SHA-1
        try:
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA1()  # Vérification avec SHA-1
            )
            print("Signature valide : le message est authentique.")
        except Exception as e:
            print("Échec de la vérification de la signature :", e)


    def rsa(self):
        # Charger le fichier keystore.p12
        keystore_path = "keystore.p12"
        keystore_password = b"mdp"  # Mot de passe du keystore

        # Charger la clé privée, le certificat et les certificats CA depuis le keystore
        with open(keystore_path, "rb") as keystore_file:
            private_key, certificate, additional_certs = load_key_and_certificates(
                keystore_file.read(),
                password=keystore_password
            )

        # Afficher le certificat et la clé privée pour vérifier
        print("Certificat chargé :", certificate)
        print("Clé privée chargée :", private_key)
        # Message à chiffrer
        message = "Bonjour je suis un message drole".encode("utf-8")
        print(message)
        # Chiffrement avec la clé publique extraite du certificat
        encrypted_message = certificate.public_key().encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Message chiffré :", encrypted_message)
        if self.sclient.fileno() != -1:  # Vérifie si le socket est toujours ouvert
            self.sclient.sendall(encrypted_message)
        else:
            print("Le socket est fermé.")

        self.sclient.close()







