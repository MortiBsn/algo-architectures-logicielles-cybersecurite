from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import tempfile

def load_p12_to_pem(p12_file, password):
    # Read the P12 file
    with open(p12_file, "rb") as file:
        p12_data = file.read()
    
    # Load the key, certificate, and CA certificates
    private_key, certificate, additional_certs = load_key_and_certificates(p12_data, password)
    
    # Export key and certificate to PEM format
    key_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )
    cert_pem = certificate.public_bytes(Encoding.PEM)
    
    # # Write to temporary files
    # key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    # cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    
    # key_file.write(key_pem)
    # cert_file.write(cert_pem)
    
    # key_file.close()
    # cert_file.close()
    
    # print("Loaded key and certificate from P12 keystore.")
    return key_pem, cert_pem

def load_public_key(filepath):
    with open(filepath, "rb") as key_file:
        return load_pem_public_key(key_file.read())

def verify_signature(public_key, message, signature):
    """Verify the message signature using the client's public key."""
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def load_private_key(filepath, password=None):
    with open(filepath, "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=password)

def sign_message(private_key, message):
    """Sign the message using the client's private key."""
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature