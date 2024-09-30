from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import md5

class Des:
    def __init__(self):
        self.key = b'2X\xb9\xae\x97\xe5^EI2Ou\xfda\x83\x1f\x8cn\xbf\xa1>*\xa1\xf4'
        self.cipher = DES3.new(self.key, DES3.MODE_ECB)
        self.block_size = DES3.block_size


    def encrypt(self, msg):
        padded_msg = pad(msg.encode(), self.block_size)
        encrypted_msg = self.cipher.encrypt(padded_msg)
        return encrypted_msg

    def decrypt(self, encrypted_msg):
        decrypted_msg = self.cipher.decrypt(encrypted_msg)
        unpadded_msg = unpad(decrypted_msg, self.block_size)
        return unpadded_msg.decode()



    def Encrypt(self):
        test = 0

    def Decrypt(self):
        test = 0