import socket
import ssl
import tempfile
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from certificates.library import load_key_and_cert_from_keystore


def send_acq_to_server(acq_data, keystore_path, keystore_password):
    """
    Envoie une requête d'accès au serveur ACS après avoir chargé le certificat et la clé privée.
    """
    print("Envoi de la requête d'accès au serveur ACS...")
    try:
        # Charger le certificat et la clé privée du keystore
        private_key, cert = load_key_and_cert_from_keystore(keystore_path, keystore_password)
        
        if cert is None or private_key is None:
            print("Impossible de charger le certificat et la clé privée.")
            return
        
        # Créer des fichiers temporaires pour la clé privée et le certificat
        with tempfile.NamedTemporaryFile(delete=False) as certfile, \
             tempfile.NamedTemporaryFile(delete=False) as keyfile:
            certfile_name = certfile.name
            keyfile_name = keyfile.name
            
            # Sérialiser le certificat et la clé privée dans les fichiers temporaires
            with open(certfile_name, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(keyfile_name, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Créer le contexte SSL
            context = ssl.create_default_context()
            context.load_cert_chain(certfile=certfile_name, keyfile=keyfile_name)
        
        # Connexion sécurisée au serveur
        with socket.create_connection(('localhost', 8443)) as client_socket:
            with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket:
                print(f"Connexion sécurisée établie avec {secure_socket.getpeername()}")
                
                # Envoi de la requête d'accès
                secure_socket.send(acq_data.encode())
                
                # Recevoir la réponse
                response = secure_socket.recv(1024)
                print(f"Réponse du serveur : {response.decode()}")
    except Exception as e:
        print(f"Erreur lors de la communication avec le serveur ACS : {e}")

if __name__ == "__main__":
    keystore_path = "certificates/keystore_acq.p12"  # Chemin du keystore .p12
    keystore_password = "HEPL"  # Mot de passe du keystore
    
    acq_data = "ACCESS_GRANTED"  # Requête d'accès
    send_acq_to_server(acq_data, keystore_path, keystore_password)
