import socket
def change_letter(letter,key):
    num = ord(letter) - key

    if num > 122 :
        num-= 26

    return chr(num)

def cesar(message, key):
    crypted =""
    for letter in message:
        if letter == " ":
            crypted += " "
        else:
            crypted += change_letter(letter, key)

    return crypted

sserveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sserveur.bind(('127.0.0.1',54321))
sserveur.listen(1)
while True :
    print(f"Waiting for client...")
    (sclient, adclient) = sserveur.accept()
    print(f"Talking on port {adclient[1]}")
    data = sclient.recv((4096))
    data = data.decode()
    print("Crypted data : " + data)
    data = cesar(data, 5)
    print(data)
    sclient.close()
sserveur.close()