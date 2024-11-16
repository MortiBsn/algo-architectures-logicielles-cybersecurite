from client import Client
import des
import aes
import time

def sending_message(client):
    client.connect()
    client.txt = "I am the message hello world "
    client.mode.encrypt(client.txt)
    print(client.txt)
    client.send_data()

des = des.Des()
client = Client(des)
sending_message(client)

# Waiting one second so no port prob
time.sleep(1)

aes = aes.Aes()
client2 = Client(aes)
sending_message(client2)

# connection
