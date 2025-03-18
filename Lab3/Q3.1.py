from pwn import *
from Crypto.Hash import SHA256

host = '0.tcp.ap.ngrok.io'
port = 16224
r = remote(host, port)

chal_byte = r.recvuntil(b'$ ')
chal_str = chal_byte.decode('utf-8').strip()
print(f"Received: {chal_str}")

print('1') 
r.sendline(b'1') 

question = r.recvuntil(b"$").decode().strip()
print(f"Received question:\n{question}")

lines = question.split("\n")

uuids = []
hashes = []
for line in lines:
    if "UUID:" in line:
        uuids.append(line.split(":")[1].strip())
    elif "Hash(UUID):" in line:
        hashes.append(line.split(":")[1].strip())

results = []
for i in range(20): 
    uuid = uuids[i]
    expected_hash = hashes[i]

    h = SHA256.new()
    h.update(uuid.encode())  
    computed_hash = h.hexdigest()  
    if computed_hash == expected_hash:
        results.append('Y') 
    else:
        results.append('N')

result_str = ''.join(results)
print("Result:", result_str)

r.sendline(result_str.encode())
print("[DEBUG] Sent result to server")

r.close()
