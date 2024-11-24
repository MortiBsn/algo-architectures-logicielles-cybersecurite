import socket
import random
from aes import Aes  # Importation de la classe Aes


class ServerAES:
    def __init__(self, mode):
        self.mode = mode  # mode est une instance de Aes
        self.on = True

    def run(self):
        p = 23  # Nombre premier (petit ici mais en général plus grand)
        g = 5  # Générateur

        # Génération de la clé privée et publique du serveur
        private_key = random.randint(1, p - 1)
        public_key = pow(g, private_key, p)

        # Créer l'objet AES (initialement sans clé partagée)
        aes = Aes()

        # Créer la socket du serveur
        sserveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sserveur.bind(('127.0.0.1', 54321))
        sserveur.listen(1)
        print(f"Serveur en attente de connexion sur le port 54321...")

        # Accepter la connexion du client
        (sclient, adclient) = sserveur.accept()
        print(f"Connexion établie avec {adclient[0]} sur le port {adclient[1]}")

        # Envoi de la clé publique du serveur au client
        sclient.send(str(public_key).encode())

        # Réception de la clé publique du client
        client_public_key = int(sclient.recv(1024).decode())

        # Calcul de la clé partagée
        shared_key = pow(client_public_key, private_key, p)
        print(f"Clé partagée calculée : {shared_key}")

        # Initialisation de l'objet AES avec la clé partagée
        aes.key = shared_key.to_bytes(16, byteorder='big')  # Convertir la clé partagée en bytes
        print(f"Clé AES initialisée pour le chiffrement.")

        # Passer l'objet aes à l'instance de Server
        self.mode = aes

        # Le serveur peut maintenant traiter les données chiffrées
        data = sclient.recv(4096)
        print("données reçues non déchiffré :")
        print(data)
        data = aes.decrypt(data)  # Déchiffrement des données reçues
        print(f"Message déchiffré : {data}")

        # Fermer la connexion
        sclient.close()
        sserveur.close()

        print("Fin de la communication.")