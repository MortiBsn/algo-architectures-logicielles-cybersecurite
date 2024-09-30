import socket
import des
class Client ():
    def __init__(self, mode):
        self.mode = mode
        self.sclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.txt = ""

    def connect(self):
        self.sclient.connect(('127.0.0.1',54321))
        print(f"Serveur @IP = {self.sclient.getpeername()[0]}")
        print(f"Port = {self.sclient.getpeername()[1]}")
        print(f"Port used = {self.sclient.getsockname()[1]}")

    def send_data(self):
        self.txt = self.mode.encrypt(self.txt)
        self.sclient.send(self.txt)
        self.sclient.close()
        print("Done with communication")