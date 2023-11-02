from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from ggplot import aes
import hashlib

# Message to hash
PM = "S1NVT1NUNjV7RWFzN19CMzR5X0wzbW9vTl9TcXUxenl9"

# Create an MD5 hash of the message
md5 = hashlib.md5()
md5.update(PM.encode())
hashed_message = md5.hexdigest()

# Print the results
print("Original Message:   ", PM)
print("Hashed Message (MD5):  ", hashed_message)


# Generate a random encryption key
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)

# Message to encrypt
PM = "This is another secret message."

# Encrypt the message
ciphertext, tag = cipher.encrypt_and_digest(PM.encode())
nonce = cipher.nonce

# Decrypt the message
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode()

# Print the results
print("Original Message:   ", PM)
print("Encrypted Message:  ", b64encode(ciphertext).decode())
print("Decrypted Message:  ", decrypted_message)
