import des
from server import Server
import aes
import hashlib


print("DES")
des = des.Des()
server = Server(des)

print("*" * 100)
print("AES")

aes = aes.Aes()
server2 = Server(aes)
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
