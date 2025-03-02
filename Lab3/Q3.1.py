from pwn import *
from Crypto.Hash import SHA256

host = '172.26.201.109' 
port = 3333
r = remote(host, port)

chal_byte = r.recvuntil(b'$ ')
chal_str = chal_byte.decode('utf-8').strip()
print(f"Received: {chal_str}")

print('1') 
r.sendline(b'1') 

# รับข้อความ UUIDs และ Hashes
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
for i in range(20):  # ทำแค่ 20 ครั้ง
    uuid = uuids[i]
    expected_hash = hashes[i]

    h = SHA256.new()
    h.update(uuid.encode())  # ให้ข้อมูล UUID ไปยัง SHA256
    computed_hash = h.hexdigest()  # คำนวณค่า hash
    if computed_hash == expected_hash:
        results.append('Y')  # ถ้าตรงกันให้ใส่ Y
    else:
        results.append('N')  # ถ้าไม่ตรงกันให้ใส่ N

result_str = ''.join(results)
print("Result:", result_str)

r.sendline(result_str.encode())
print("[DEBUG] Sent result to server")

r.close()
