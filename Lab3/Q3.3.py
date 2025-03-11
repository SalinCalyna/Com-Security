from pwn import *
from Crypto.Hash import MD5

host = '172.26.201.109'
port = 3333
r = remote(host, port)

# Receive data from the server
chal_byte = r.recvuntil(b'$ ')
chal_str = chal_byte.decode('utf-8').strip()
print(f"Received: {chal_str}")

print('3')
r.sendline(b'3')

question = r.recvuntil(b"$").decode().strip()
print(f"Received question:\n{question}")

lines = question.split("\n")

# Define the oHashPlus function
def oHashPlus(message):
    message = message.encode()  # Convert the message to bytes
    h = MD5.new(message)  # Compute the MD5 hash
    return h.hexdigest()[:10]  # Take the first 10 hex digits

# Find a collision
username1 = " "
username2 = " "

hash1 = oHashPlus(username1)
hash2 = oHashPlus(username2)

print(f"Username 1: {username1}, Hash: {hash1}")
print(f"Username 2: {username2}, Hash: {hash2}")

if hash1 == hash2:
    print("Collision found!")
else:
    print("No collision")
