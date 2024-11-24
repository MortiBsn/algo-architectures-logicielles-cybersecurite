import random
import socket
import des
from HmacMD5 import HmacMd5
from aes import Aes
class Client ():
    def __init__(self, mode):
        self.mode = mode
        self.sclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.txt = ""

    def connect(self):
        self.sclient.connect(('127.0.0.1',54321))
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



