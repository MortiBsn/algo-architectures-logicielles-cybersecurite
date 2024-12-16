import socket
import ssl
from cryptolib import load_public_key, verify_signature, sign_message, load_private_key
import random
import threading
import time
from ports import PORT_AUTH, PORT_MONEY, PORT_RESPONSE

# Server settings
HOST = '127.0.0.1'  # Localhost



# Paths to SSL certificate and key files
CERT_FILE = 'acs.cer'
KEY_FILE = 'acs.key'

codes = []
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('certificates/acs.cer', 'certificates/acs.key')
context.load_verify_locations('certificates/myCA.cer')

def generate_authentification_code():
    code = ""

    while(len(code) < 5):
        code += str(random.randint(0, 9))
    return code

def luhn_check(card_number):
    """Vérifie la validité d'une carte de crédit avec l'algorithme de Luhn."""
    card_number = card_number.replace(" ", "")  # Retirer les espaces
    if not card_number.isdigit():
        return False  # Le numéro ne doit contenir que des chiffres
    
    total = 0
    reverse_digits = card_number[::-1]  # Inverser les chiffres pour commencer par la droite
    
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:  # Doubler chaque deuxième chiffre
            n *= 2
            if n > 9:  # Soustraire 9 si le résultat est supérieur à 9
                n -= 9
        total += n
    
    return total % 10 == 0  # Vérifier si la somme est divisible par 10

def start_secure_server():
    # Create a standard TCP socket
    
    client_public_key = load_public_key("certificates/client.pub")
    serverPrivateKey = load_private_key("certificates/acs.key")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT_AUTH))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            try:
                while True:
                    # Accept a connection
                    client_socket, addr = ssock.accept()
                    print(f"Connection from {addr} established.")
                    
                    # Communicate securely
                    data = client_socket.recv(1024)
                    if b'||' in data:
                        message, signature = data.split(b'||', 1)
                        message = message.decode('utf-8')

                        if verify_signature(client_public_key, message, signature):
                            print(f"Verified message: {message}")
                            date, cardNumber = message.split('_')
                            print("The date is : " + str(date))
                            if(luhn_check(cardNumber)):
                                print("The card number is valid")
                                generatedCode = generate_authentification_code()
                                while generatedCode in codes:
                                    generatedCode = generate_authentification_code()
                                codes.append(generatedCode)
                                print(f"Token generated : {generatedCode}")
                                serverSignature = sign_message(serverPrivateKey, generatedCode)
                                client_socket.sendall(generatedCode.encode('utf-8') + b'||' + serverSignature)
                            else:
                                print("The card number is invalid")
                    print(f"Received: {data}")
                    client_socket.close()
                    print("Connection closed.")
            except KeyboardInterrupt:
                print("Server shutting down...")
            finally:
                ssock.close()

def waitACQResponse():
    print("Thread started")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT_MONEY))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                client_socket, addr = ssock.accept()
                message = ""

                code = client_socket.recv(1024)
                code = code.decode('utf-8')
                if code in codes:
                    message = "ACK"
                    codes.remove(code)
                else:
                    message = "NACK"
                
                sendResponseToWebServer(message)
                client_socket.close()

def sendResponseToWebServer(response):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as client_socket:
            client_socket.connect((HOST, PORT_RESPONSE))
            client_socket.sendall(response.encode('utf-8'))
            print("Response sent to web server")
            client_socket.close()

if __name__ == "__main__":
    thread = threading.Thread(target=waitACQResponse)
    thread.start()
    start_secure_server()
