from cryptography.hazmat.primitives import serialization
import ssl
import tempfile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
import tempfile
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization


def load_key_and_cert_from_keystore(keystore_path, password):
    """
    Charger la clé privée et le certificat depuis un fichier keystore PKCS#12.
    :param keystore_path: Chemin du keystore .p12
    :param password: Mot de passe pour déchiffrer le keystore
    :return: clé privée et certificat
    """
    with open(keystore_path, 'rb') as f:
        keystore_data = f.read()

    # Charger le keystore PKCS#12
    private_key, certificate, additional_certificates = load_key_and_certificates(
        keystore_data, password.encode(), default_backend()
    )
    return private_key, certificate


def load_ca_from_truststore(truststore_path, truststore_password=None):
    print(f"Début de la fonction load_ca_from_truststore avec le truststore: {truststore_path}")
    try:
        # Lire le truststore
        with open(truststore_path, 'rb') as f:
            keystore_data = f.read()
            print(f"Truststore lu avec succès, taille des données: {len(keystore_data)} octets")

        # Charger le keystore PKCS#12
        private_key, cert, additional_certificates = pkcs12.load_key_and_certificates(
            keystore_data, truststore_password.encode() if truststore_password else None, backend=None
        )

        # Affichage des informations du truststore
        print("Truststore chargé :")
        print(f"Clé privée: {private_key is not None}")
        print(f"Certificat: {cert is not None}")
        print(f"Nombre de certificats supplémentaires: {len(additional_certificates) if additional_certificates else 0}")

        if cert:
            print("Certificat trouvé dans le truststore.")
            # Convertir le certificat en PEM
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            print(f"Certificat converti en PEM. Taille: {len(cert_pem)} octets.")

            # Sauvegarder dans un fichier temporaire
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_cert_file:
                temp_cert_file.write(cert_pem)
                temp_cert_file.flush()  # Assurer que les données sont écrites

                # Retourner le chemin du fichier temporaire contenant le certificat PEM
                print(f"Certificat enregistré dans un fichier temporaire: {temp_cert_file.name}")
                return temp_cert_file.name
        elif additional_certificates:
            print("Certificat principal non trouvé, mais certificats supplémentaires trouvés.")
            for idx, additional_cert in enumerate(additional_certificates):
                print(f"Certificat supplémentaire {idx + 1}:")
                # Convertir le certificat supplémentaire en PEM
                additional_cert_pem = additional_cert.public_bytes(serialization.Encoding.PEM)
                print(f"Taille du certificat supplémentaire {idx + 1} en PEM: {len(additional_cert_pem)} octets.")
                # Sauvegarder dans un fichier temporaire
                with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_cert_file:
                    temp_cert_file.write(additional_cert_pem)
                    temp_cert_file.flush()  # Assurer que les données sont écrites

                    # Retourner le chemin du fichier temporaire contenant le certificat PEM
                    print(f"Certificat supplémentaire {idx + 1} enregistré dans un fichier temporaire: {temp_cert_file.name}")
                    return temp_cert_file.name
        else:
            print("Aucun certificat trouvé dans le truststore.")
            return None

    except Exception as e:
        print(f"Erreur lors du chargement du truststore : {e}")
        return None
