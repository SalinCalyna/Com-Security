from pwn import *

# เชื่อมต่อไปยังเซิร์ฟเวอร์
host = '172.26.201.109'
port = 1111

r = remote(host, port)

def hex_to_byte(hex_str):
    return bytes.fromhex(hex_str)

def xor_byte(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))  # ใช้ zip() จับคู่ byte แล้ว XOR กัน

# รับข้อความต้อนรับ
response = r.recvline().decode('utf-8')

# ส่งตัวเลือก '6' เพื่อเลือกโจทย์ OTP Attack
r.sendline(b'6')
print(response.strip() + ' 6')

# รับคำถามจากเซิร์ฟเวอร์
question = r.recvline().decode('utf-8')
print(question.strip())

question = r.recvline().decode('utf-8')
print(question.strip())

# รับ plaintext ที่รู้ล่วงหน้า
response = r.recvline().decode('utf-8')
print(response.strip())
plaintext_byte = response.split(":")[1].strip().encode()

# รับ ciphertext ตัวแรก
response = r.recvline().decode('utf-8')
print(response.strip())
cipher1_hex = response.split(":")[1].strip()
cipher1_byte = hex_to_byte(cipher1_hex)

# รับ ciphertext ตัวที่สอง
response = r.recvline().decode('utf-8')
print(response.strip())
cipher2_hex = response.split(":")[1].strip()
cipher2_byte = hex_to_byte(cipher2_hex)

# แสดงค่าที่ได้รับ
print("PlainText:", plaintext_byte)
print("Cipher1:", cipher1_byte)
print("Cipher2:", cipher2_byte)

# คำนวณค่า Key
key = xor_byte(plaintext_byte, cipher1_byte)
print("Recovered Key:", key)

# ใช้ Key ถอดรหัส Cipher2
answer = xor_byte(cipher2_byte, key)
print("Recovered Plaintext 2:", answer)

# ส่งข้อความที่ถอดรหัสแล้วกลับไปยังเซิร์ฟเวอร์
r.sendline(answer)

# รับข้อความตอบกลับจากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8').strip()
print(response)
