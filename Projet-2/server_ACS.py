import ssl
import socket
from certificates.library import load_key_and_cert_from_keystore, load_ca_from_truststore
from cryptography.hazmat.primitives import serialization
import tempfile


def start_acs_server():
    # Charger la clé et le certificat depuis le keystore PKCS#12 pour ACS
    private_key, cert = load_key_and_cert_from_keystore("certificates/keystore_acs.p12", "HEPL")

    # Créer un contexte SSL pour le serveur ACS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Sauvegarder temporairement le certificat et la clé privée dans des fichiers
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as cert_file, \
         tempfile.NamedTemporaryFile(delete=False, mode='wb') as key_file:
        # Écrire le certificat dans le fichier temporaire
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_file.flush()  # Assurer que les données sont écrites immédiatement
        
        # Écrire la clé privée dans le fichier temporaire
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,  # Changer en PKCS8 si nécessaire
            encryption_algorithm=serialization.NoEncryption()
        ))
        key_file.flush()  # Assurer que les données sont écrites immédiatement

        # Charger le certificat et la clé dans le contexte SSL
        context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)

    # Charger le certificat CA depuis le truststore
    ca_cert_file = load_ca_from_truststore("certificates/truststore_ca.p12", "HEPL")
    if ca_cert_file:
        context.load_verify_locations(cafile=ca_cert_file)
    else:
        print("Erreur lors du chargement du truststore")

    context.verify_mode = ssl.CERT_REQUIRED  # Demande un certificat client

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('0.0.0.0', 8443))
        sock.listen(5)

        print("ACS Server démarré, en attente de connexions...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                print(f"Connexion de {addr}")

                # Lire les données du client
                data = conn.recv(1024).decode()
                print(f"Reçu : {data}")

                # Envoyer une réponse
                conn.sendall(b"Message bien recu par ACS!")
                conn.close()


if __name__ == "__main__":
    start_acs_server()