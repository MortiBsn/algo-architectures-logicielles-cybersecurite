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


# Waiting one second so no port prob
time.sleep(1)
aes = Aes()
client2 = Client(aes)
client2.txt = "I am the message hello world "
client2.connect()
client2.send_data_aes()

time.sleep(1)


client3 = Client(None)
client3.connect()
client3.txt = "I am the message hello world "
client3.send_data_HmacMd5("ma_clé_secrète")




# connection
