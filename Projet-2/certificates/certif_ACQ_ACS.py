import ssl
from cryptography.hazmat.primitives.serialization import Encoding, BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates, load_key_and_certificates
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from cryptography import x509
  

def generate_key_and_cert(common_name, ca_cert=None, ca_key=None, is_ca=False):
    # Générer une clé privée RSA
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Construire un sujet pour le certificat
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Wallonie"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Liège"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HEPL-DebEvrBis"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Si c'est un certificat signé par une CA, utiliser le CA comme émetteur
    if ca_cert and ca_key:
        issuer = ca_cert.subject

    # Construire le certificat
    cert_builder = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.now(timezone.utc)) \
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

    # Ajouter l'extension CA si nécessaire
    if is_ca:
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)

    # Signer le certificat
    cert = cert_builder.sign(
        private_key=ca_key if ca_key else key,
        algorithm=hashes.SHA256(),
    )

    return key, cert


def create_keystore(file_name, password, private_key, certificate, additional_certificates=None):
    # Utiliser NoEncryption si aucun mot de passe n'est défini
    encryption_algorithm = NoEncryption() if not password else BestAvailableEncryption(password.encode())

    p12_data = serialize_key_and_certificates(
        name=b"My Keystore",
        key=private_key,
        cert=certificate,
        cas=additional_certificates,
        encryption_algorithm=encryption_algorithm
    )

    with open(file_name, "wb") as f:
        f.write(p12_data)
    print(f"Keystore '{file_name}' créé avec succès.")


# Étape 1 : Générer le certificat CA
ca_key, ca_cert = generate_key_and_cert(common_name="My CA", is_ca=True)

# Étape 2 : Générer le certificat ACS signé par la CA
acs_key, acs_cert = generate_key_and_cert("ACS", ca_cert=ca_cert, ca_key=ca_key)

# Étape 3 : Générer le certificat ACQ signé par la CA
acq_key, acq_cert = generate_key_and_cert("ACQ", ca_cert=ca_cert, ca_key=ca_key)

# Étape 4 : Créer les keystores PKCS#12
create_keystore("certificates/keystore_acs.p12", "HEPL", acs_key, acs_cert, [ca_cert])
create_keystore("certificates/keystore_acq.p12", "HEPL", acq_key, acq_cert, [ca_cert])

# Étape 5 : Créer le truststore PKCS#12 contenant uniquement le certificat CA
create_keystore("certificates/truststore_ca.p12", "HEPL", None, None, [ca_cert])