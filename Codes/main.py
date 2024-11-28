import random

import des
from server import Server
from aes import Aes
from HmacMD5 import HmacMd5
import hashlib


print("DES")
des = des.Des()
server = Server(des)
server.des()

print("*" * 100)
print("AES")
aes = Aes()
server2 = Server(None)
server2.aes()
print("end")

print("*" *100)
print("SHA-1")
# Hashing with sha-1
message = "Ceci est un message à hacher"
print(message)
sha1_hash = hashlib.sha1()
sha1_hash.update(message.encode('utf-8'))
hashed_message = sha1_hash.hexdigest()
print(hashed_message)

print("*"*100)
print("HMAC-MD5")
server3 = Server(None)
server3.hmacmd5("ma_clé_secrète")

print("*"*100)
print("SHA1-RSA")
server4 = Server(None)
server4.sharsa()

print("*"*100)
print("RSA")
server5 = Server(None)
server5.rsa()
