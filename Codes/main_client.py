import client
import des
import server

des = des.Des()
client = client.Client(des)
# connection
client.connect()
client.txt = "I am the message hello world "
print(client.txt)
client.mode.encrypt(client.txt)
print (client.txt)
client.send_data()