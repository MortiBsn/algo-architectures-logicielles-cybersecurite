import ssl
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from certificates.library import load_key_and_cert_from_keystore, load_ca_from_truststore

from server_ACS import PORT_AUTH

# Charger la clé privée
private_key, cert = load_key_and_cert_from_keystore("certificates/client_keystore.p12", password="Student1")

# Créer le message
message = b"credit_card_number=1234567890123456&expiration_date=12/24"

# Signer le message
signature = private_key.sign(
    message,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Envoyer au serveur ACS
context = ssl.create_default_context()
context.load_cert_chain(certfile="certificates/client_certificate.pem", keyfile="certificates/client_private_key.pem", password="Student1")
context.load_verify_locations(cafile="certificates/web_cert.pem")
with socket.create_connection(('localhost', PORT_AUTH)) as sock:
    with context.wrap_socket(sock, server_hostname='ACS') as ssock:
        ssock.sendall(message + b"\nSignature:" + signature)