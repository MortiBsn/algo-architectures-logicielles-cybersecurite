import random
import socket
import struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1

from HmacMD5 import HmacMd5
from aes import Aes

class Server:
    def __init__(self, mode):
        self.mode = mode
        self.sserveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.on = True
    def des(self):
        self.sserveur.bind(('127.0.0.1', 12345))
        self.sserveur.listen(1)
        print(f"Waiting for client...")
        (sclient, adclient) = self.sserveur.accept()
        print(f"Talking on port {adclient[1]}")
        data = sclient.recv((4096))
        print(data)
        data = self.mode.decrypt(data)
        print(data)
        #print(data.decode())
        sclient.close()
        self.sserveur.close()
    def aes(self):
        p = 23  # Nombre premier (petit ici mais en général plus grand)
        g = 5  # Générateur

        # Génération de la clé privée et publique du serveur
        private_key = random.randint(1, p - 1)
        public_key = pow(g, private_key, p)

        # Créer l'objet AES (initialement sans clé partagée)
        aes = Aes()
        self.sserveur.bind(('127.0.0.1', 12345))
        self.sserveur.listen(1)
        print(f"Serveur en attente de connexion sur le port 12345...")

        # Accepter la connexion du client
        (sclient, adclient) = self.sserveur.accept()
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
        self.sserveur.close()

        print("Fin de la communication.")

    def hmacmd5(self,key_hmac):
        self.sserveur.bind(('127.0.0.1', 12345))
        self.sserveur.listen(1)
        print(f"Waiting for client...")
        (sclient, adclient) = self.sserveur.accept()
        print(f"Talking on port {adclient[1]}")
        message = sclient.recv(1024).decode()
        hmac_value = sclient.recv(64).decode()
        hmac_auth = HmacMd5(key_hmac)
        print("HMAC reçu : " ,hmac_value )
        if hmac_auth.verify_hmac(message, hmac_value):
            print("HMAC Vérifié avec succès !")

            print("Message reçu:", message)
        else:
            print("Échec de la vérification HMAC. Le message a été modifié.")

        sclient.close()
        self.sserveur.close()
        print("Fin de la communication.")


    def sharsa(self):
        # Génération des clés RSA

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Exporter la clé publique au format PEM pour envoi

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        message = "Voici un message signé par le serveur.".encode('utf-8')  # Encodage en bytes

        # Signer le message avec SHA-1
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA1()  # Utilisation de SHA-1 pour la signature
        )

        self.sserveur.bind(('127.0.0.1', 12345))
        self.sserveur.listen(1)
        print("Serveur en attente d'une connexion...")

        conn, addr = self.sserveur.accept()
        print(f"Connexion établie avec {addr}")

        conn.sendall(struct.pack("I", len(public_pem)))  # Taille de la clé publique
        conn.sendall(struct.pack("I", len(message)))  # Taille du message
        conn.sendall(struct.pack("I", len(signature)))  # Taille de la signature

        conn.sendall(public_pem)  # Envoyer la clé publique
        conn.sendall(message)  # Envoyer le message
        conn.sendall(signature)  # Envoyer la signature

        conn.close()
        self.sserveur.close()


    def rsa(self):
        #Récupération clé
        keystore_path = "keystore.p12"
        keystore_password = b"mdp"  # Mot de passe du keystore

        # Charger la clé privée, le certificat et les certificats CA depuis le keystore
        with open(keystore_path, "rb") as keystore_file:
            private_key, certificate, additional_certs = load_key_and_certificates(
                keystore_file.read(),
                password=keystore_password
            )

        self.sserveur.bind(('127.0.0.1', 12345))
        self.sserveur.listen(1)
        print(f"Serveur en attente de connexion sur le port 12345...")

        # Accepter la connexion du client
        (sclient, adclient) = self.sserveur.accept()
        print(f"Connexion établie avec {adclient[0]} sur le port {adclient[1]}")
        encrypted_message = sclient.recv(4096)
        print(encrypted_message)
        # Déchiffrement avec la clé privée extraite du keystore
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("Message déchiffré :", decrypted_message.decode("utf-8"))

        sclient.close()
        self.sserveur.close()



