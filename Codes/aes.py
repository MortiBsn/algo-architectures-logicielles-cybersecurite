from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class Aes:
    def __init__(self):
        self.key = b'\x1a3\xf1u\xa5x-=\xf2\xa0\xa7\xa7{\xed0>'
        # Block size for AES is 16 bytes
        self.block_size = AES.block_size

    def encrypt(self, msg):
        # Generate a random IV for each encryption
        iv = get_random_bytes(self.block_size)  # AES block size is 16 bytes

        # Initialize the AES cipher with the key and the random IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Pad the message to make it a multiple of the block size
        padded_msg = pad(msg.encode(), self.block_size)

        # Encrypt the padded message
        encrypted_msg = cipher.encrypt(padded_msg)

        # Return both the IV and the encrypted message (IV is needed for decryption)
        return iv + encrypted_msg  # Prepend the IV to the encrypted message

    def decrypt(self, encrypted_msg):
        # Extract the IV from the beginning of the encrypted message
        iv = encrypted_msg[:self.block_size]
        encrypted_data = encrypted_msg[self.block_size:]

        # Initialize the AES cipher with the key and the extracted IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Decrypt the message
        decrypted_msg = cipher.decrypt(encrypted_data)

        # Unpad the decrypted message to retrieve the original plaintext
        unpadded_msg = unpad(decrypted_msg, self.block_size)

        # Return the decrypted message as a string
        return unpadded_msg.decode('utf-8')  # Decode bytes back to string