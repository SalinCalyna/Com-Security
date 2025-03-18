from pwn import *
from Crypto.Hash import MD5
import re

host = '0.tcp.ap.ngrok.io'
port = 16224
r = remote(host, port)

chal_byte = r.recvuntil(b'$ ')
chal_str = chal_byte.decode('utf-8').strip()
print(f"Received: {chal_str}")

print('2')
r.sendline(b'2')

question = r.recvuntil(b"$").decode().strip()
print(f"Received question:\n{question}")

def oHash(message):
    message = str.encode(message)
    h = MD5.new(message)
    return h.hexdigest()[:5]

target_hash_match = re.search(r'[a-f0-9]{5}', question)
if target_hash_match:
    target_hash = target_hash_match.group(0)
    print(f"Target hash: {target_hash}")
else:
    print("Could not find the target hash")
    r.close()
    exit()

found = False
for i in range(1000000):
    password = f"{i:06}"
    if oHash(password) == target_hash:
        print(f"Password found: {password}")
        r.sendline(password.encode('utf-8'))
        found = True
        r.interactive()
        break

if not found:
    print("Password not found")
r.close()
