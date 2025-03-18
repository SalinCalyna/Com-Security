import json
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

# ตั้งค่าการเชื่อมต่อ
host = '172.26.201.109'
port = 2222
r = remote(host, port)

# รับข้อความเริ่มต้นจากเซิร์ฟเวอร์
r.recvuntil(b'$')

# ส่งตัวเลือก '1' ไปยังเซิร์ฟเวอร์
r.sendline(b'1')

# รับคำถามที่มีค่า IV
chal_bytes = r.recvuntil(b'$')
chal_str = chal_bytes.decode('utf-8')

print(chal_str)  # แสดงข้อมูลที่ได้รับ

# ดึงค่า IV โดยใช้ regex
iv_match = re.search(r'IV: ([0-9a-fA-F]+)', chal_str)
if iv_match:
    iv_hex = iv_match.group(1)
    iv_bytes = bytes.fromhex(iv_hex)
    print("Extracted IV (bytes):", iv_bytes)
else:
    print("IV not found!")
    r.close()
    exit()

# ตั้งค่า Key และข้อความที่ต้องการเข้ารหัส
key = b"\x00" * 16
plaintext = b'Salintip'

# เข้ารหัสด้วย AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))

# แปลง Ciphertext เป็น Hex
cipher_hex = ct_bytes.hex()
print("Ciphertext (hex):", cipher_hex)

# ส่ง Ciphertext กลับไปที่เซิร์ฟเวอร์
r.sendline(cipher_hex.encode('utf-8'))

# แสดงผลลัพธ์ที่ได้รับจากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8').strip()
print("Server Response:", response)
