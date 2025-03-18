from pwn import *  # นำเข้า pwntools สำหรับการเชื่อมต่อเครือข่าย

# กำหนด IP และพอร์ตของเซิร์ฟเวอร์
host = '172.26.201.109'
port = 1111

# เชื่อมต่อไปยังเซิร์ฟเวอร์
r = remote(host, port)

# ฟังก์ชันแปลงค่าจาก Hexadecimal เป็น Bytes
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

# ฟังก์ชัน XOR ระหว่างข้อมูลสองชุด
def xor_bytes(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

# รับข้อความต้อนรับจากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8')

# ส่งตัวเลือก '4' เพื่อเลือกโจทย์เกี่ยวกับ One-Time Pad (OTP)
r.sendline(b'4')
print(response + '4')

# รับคำถามจากเซิร์ฟเวอร์
question = r.recvline().decode('utf-8')
print(question)

# รับ ciphertext ในรูปแบบ hex จากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8')
print(response)
cipherText_hex = response.split(":")[1].strip()  # ดึงส่วนของข้อความเข้ารหัสที่อยู่หลังเครื่องหมาย ':'
cipherText_byte = hex_to_bytes(cipherText_hex)  # แปลงจาก hex เป็น byte
print(cipherText_byte)

# รับ OTP key ในรูปแบบ hex จากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8')
print(response)
otp_hex = response.split(":")[1].strip()  # ดึง OTP key ที่อยู่หลังเครื่องหมาย ':'
otp_byte = hex_to_bytes(otp_hex)  # แปลงจาก hex เป็น byte
print(otp_byte)

# ใช้ XOR ระหว่าง ciphertext และ OTP เพื่อถอดรหัส plaintext
plaintext_bytes = xor_bytes(cipherText_byte, otp_byte)
plaintext = plaintext_bytes.decode(errors=" ")  # แปลง byte กลับเป็น string

print(f"Recovered Plaintext: {plaintext}")

# ส่ง plaintext ที่ถอดรหัสได้กลับไปยังเซิร์ฟเวอร์
r.sendline(plaintext)

# รับข้อความตอบกลับสุดท้ายจากเซิร์ฟเวอร์
response = r.recvline()
print(response)
