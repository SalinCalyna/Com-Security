import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

# ตั้งค่าการเชื่อมต่อ
host = '172.26.201.109'
port = 2222
r = remote(host, port)

chal_bytes = r.recvuntil(b'$')
chal_str = chal_bytes.decode('utf-8')

r.sendline(str(1))

chal_bytes = r.recvuntil(b'$')
chal_str = chal_bytes.decode('utf-8')

print(chal_str)

key = b"\x00" * 16

plaintext = b'Salintip'

# ดึงค่า IV จากคำถาม
iv = chal_bytes.split(b'IV: ')[1].split(b'\n')[0].strip()
iv = iv.decode('utf-8') 

iv_bytes = bytes.fromhex(iv)
print("IV in bytes:", iv_bytes)

# เข้ารหัสด้วย AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))

cipher_hex = ct_bytes.hex()

print("Ciphertext (hex): ", cipher_hex)

r.sendline(cipher_hex.encode('utf-8'))
res = r.recvline()
print(res.decode('utf-8'))
