from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates


# 1. Génération d'une clé privée RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# 2. Création des informations du certificat
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "BE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Liège"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Liège"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cours"),
    x509.NameAttribute(NameOID.COMMON_NAME, "cours.com"),
])

# 3. Génération du certificat auto-signé
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=700))  # 1 an de validité
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    .sign(private_key, hashes.SHA256(), default_backend())
)

# 4. Création d'un keystore PKCS12

# Mot de passe pour protéger le keystore
password = b"mdp"

# Sérialisation en format PKCS12
p12_data = serialize_key_and_certificates(
    name=b"mon_certificat",
    key=private_key,
    cert=certificate,
    cas=None,  # Pas de CA supplémentaire
    encryption_algorithm=serialization.BestAvailableEncryption(password),
)

# 5. Sauvegarde dans un fichier keystore.p12
with open("keystore.p12", "wb") as p12_file:
    p12_file.write(p12_data)

print("Keystore PKCS12 généré : keystore.p12")
