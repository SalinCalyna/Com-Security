from pwn import *
from hashlib import md5
import random
import string

host = '0.tcp.ap.ngrok.io'
port = 16224
r = remote(host, port)

chal_str = r.recvuntil(b'$ ').decode('utf-8').strip()
print(f"Received: {chal_str}")

r.sendline(b'3')

question = r.recvuntil(b"$").decode().strip()
print(f"Received question:\n{question}")

def oHashPlus(message):
    return md5(message.encode()).hexdigest()[:10]

def random_username(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def find_collision():
    seen_hashes = {}
    attempts = 0
    while True:
        username = random_username()
        hash_value = oHashPlus(username)
        if hash_value in seen_hashes:
            print(f"Collision found after {attempts} attempts!")
            return seen_hashes[hash_value], username
        seen_hashes[hash_value] = username
        attempts += 1
        if attempts % 1000 == 0:
            print(f"Attempts: {attempts}, Hashes: {len(seen_hashes)}")

username1, username2 = find_collision()

print(f"Collision found!")
print(f"Username 1: {username1}, Hash: {oHashPlus(username1)}")
print(f"Username 2: {username2}, Hash: {oHashPlus(username2)}")

r.sendline(username1)
r.sendline(username2)

response = r.recvall().decode()
print(f"Server response: {response}")

r.close()
