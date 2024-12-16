import ssl
import socket
from cryptolib import load_private_key, load_public_key
from ports import PORT_VERIFICATION, PORT_MONEY

HOST = "127.0.0.1"

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('certificates/acq.cer', 'certificates/acq.key')
context.load_verify_locations('certificates/myCA.cer')

def start_secure_server():
    # Create a standard TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT_VERIFICATION))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            try:
                while True:
                    # Accept a connection
                    client_socket, addr = ssock.accept()
                    print(f"Connection from {addr} established.")
                    
                    # Communicate securely
                    code = client_socket.recv(1024)
                    code = code.decode('utf-8')
                    print(f"Code : {code}")
                    client_socket.close()
                    sendCodeToACS(code)
            except KeyboardInterrupt:
                print("Server shutting down...")
            finally:
                ssock.close()

def sendCodeToACS(code):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as client_socket:
            client_socket.connect((HOST, PORT_MONEY))
            client_socket.sendall(code.encode('utf-8'))
            print("Code sent to ACS")
            client_socket.close()


if __name__ == "__main__":
    start_secure_server()