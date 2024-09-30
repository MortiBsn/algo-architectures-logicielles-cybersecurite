import socket

class Server:
    def __init__(self, mode):
        self.mode = mode
        sserveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sserveur.bind(('127.0.0.1',54321))
        sserveur.listen(1)
        while True :
            print(f"Waiting for client...")
            (sclient, adclient) = sserveur.accept()
            print(f"Talking on port {adclient[1]}")
            data = sclient.recv((4096))
            print(data)
            data = self.mode.decrypt(data)
            print(data)
            #print(data.decode())
            sclient.close()
        sserveur.close()