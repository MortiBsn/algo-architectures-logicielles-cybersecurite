from client import Client
import des
from aes import Aes
import time
from HmacMD5 import HmacMd5


des = des.Des()
client = Client(des)
client.connect()
client.txt = "I am the message hello world "
client.mode.encrypt(client.txt)
print(client.txt)
client.send_data()

print("*"*100)

# Waiting one second so no port prob
time.sleep(1)
aes = Aes()
client2 = Client(aes)
client2.txt = "I am the message hello world "
client2.connect()
client2.send_data_aes()

time.sleep(1)

print("*"*100)

client3 = Client(None)
client3.connect()
client3.txt = "I am the message hello world "
client3.send_data_HmacMd5("ma_clé_secrète")


time.sleep(1)
print("*"*100)

client4 = Client(None)
client4.connect()
client4.receive_data_sha_rsa()



time.sleep(1)
print("*"*100)

client5 = Client(None)
client5.connect()
client5.rsa()