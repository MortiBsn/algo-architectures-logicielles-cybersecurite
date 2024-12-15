import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptolib import load_private_key, sign_message, verify_signature, load_public_key
from datetime import date
from ports import PORT_AUTH

# Server address
HOST = '127.0.0.1'  # Localhost

def start_secure_client():
    # Create a standard TCP socket
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_verify_locations('certificates/myCA.cer')
    
    acs_public_key = load_public_key('certificates/acs.pub')
    private_key = load_private_key('certificates/client.key')

    # Wrap the socket with SSL
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as client_socket:
            try:
                # Connect to the server
                client_socket.connect((HOST, PORT_AUTH))
                print("Connected securely to the server.")
                
                # Send a message
                message = str(date.today()) + "_5200000000001096"
                signature = sign_message(private_key, message)

                client_socket.sendall(message.encode('utf-8') + b'||' + signature)
                print("Message and signature sent.")
                
                # Receive a response
                data = client_socket.recv(1024)
                # print(f"Received from server: {response}")
                if b'||' in data:
                    message, acsSignature = data.split(b'||', 1)
                    message = message.decode('utf-8')

                    if verify_signature(acs_public_key, message, acsSignature):
                        print(f"Verified token : {message}")
            finally:
                client_socket.close()
                print("Connection closed.")

if __name__ == "__main__":
    start_secure_client()
