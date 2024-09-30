import socket

sserveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sserveur.bind(('127.0.0.1',54321))
sserveur.listen(1)
while True :
    print(f"Waiting for client...")
    (sclient, adclient) = sserveur.accept()
    print(f"Talking on port {adclient[1]}")
    data = sclient.recv((4096))
    print(data.decode())
    sclient.close()
sserveur.close()