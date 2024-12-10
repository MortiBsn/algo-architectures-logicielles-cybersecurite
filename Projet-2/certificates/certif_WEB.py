from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# Générer une clé privée RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Sauvegarder la clé privée dans un fichier PEM
with open("certificates/web_key.pem", "wb") as key_file:
    key_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Construire un certificat
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Wallonie"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Liège"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"HEPL-DebEvrBis"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

cert = x509.CertificateBuilder() \
    .subject_name(subject) \
    .issuer_name(issuer) \
    .public_key(private_key.public_key()) \
    .serial_number(x509.random_serial_number()) \
    .not_valid_before(datetime.utcnow()) \
    .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ) \
    .sign(private_key, hashes.SHA256())

# Sauvegarder le certificat dans un fichier PEM
with open("certificates/web_cert.pem", "wb") as cert_file:
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

print("Certificat auto-signé et clé privée générés avec succès !")