import socket

def change_letter(letter,key):
    num = ord(letter) + key

    if num > 122 :
        num+= 26

    return chr(num)

def cesar(message, key):
    crypted =""
    for letter in message:
        if letter == " ":
            crypted += " "
        else:
            crypted += change_letter(letter, key)

    return crypted

sclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sclient.connect(('127.0.0.1',54321))
print(f"Serveur @IP = {sclient.getpeername()[0]}")
print(f"Port = {sclient.getpeername()[1]}")
print(f"Port utilisé = {sclient.getsockname()[1]}")
key = 5
txt = input("Message : ")
txt = cesar(txt, key)
sclient.send(txt.encode())
sclient.close()
print("Done with communication")



