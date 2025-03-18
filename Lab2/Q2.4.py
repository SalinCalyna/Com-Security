import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from pwn import *
from Crypto.Util.strxor import strxor 

# ฟังก์ชันใช้แก้ไข ciphertext โดยการปรับเปลี่ยน plaintext แล้วสร้าง ciphertext ใหม่
def modify_cipher(plainText, cipherText_hex): 
    cipherText_byte = bytes.fromhex(cipherText_hex)  # แปลง ciphertext จาก hex เป็น bytes
    plainText_byte = plainText.encode('utf-8')  # แปลง plaintext เป็น bytes
    plainText_byte = pad(plainText_byte, AES.block_size)  # เติม padding ให้สอดคล้องกับ AES block size
    print(len(plainText_byte), plainText, plainText_byte)  # แสดงขนาดของ plaintext หลัง padding
    print(len(cipherText_byte))  # แสดงขนาดของ ciphertext

    # คำนวณ key โดย XOR plaintext กับ ciphertext เดิม
    key = strxor(plainText_byte, cipherText_byte)
    
    print(key)  # แสดงค่า key ที่คำนวณได้

    # สร้าง plaintext ใหม่ที่ต้องการแก้ไข
    new_P = pad(b"Your bank account balance is 10,000,000 Baht", AES.block_size)

    # คำนวณ ciphertext ใหม่โดยใช้ key และ plaintext ใหม่
    modifyCipher = strxor(key, new_P)

    print(len(modifyCipher), len(new_P))  # แสดงขนาดของ ciphertext ใหม่และ plaintext ใหม่
   
    return modifyCipher.hex()  # ส่งคืนค่า ciphertext ที่แก้ไขแล้วในรูปแบบ hex

# ตั้งค่าเซิร์ฟเวอร์
host = '172.26.201.109'
port = 2222

r = remote(host, port)  # เชื่อมต่อไปยังเซิร์ฟเวอร์

r.recvline()  # รับบรรทัดแรกจากเซิร์ฟเวอร์
r.sendline(b"4")  # ส่งตัวเลือกที่ 4 เพื่อเลือกรับข้อมูลที่ต้องการ

# อ่านและแสดงผลข้อความจากเซิร์ฟเวอร์
for i in range(2):
    response = r.recvline().decode('utf-8')
    print("res = ", response)

# รับค่า plaintext จากเซิร์ฟเวอร์
plainText = r.recvline().decode('utf-8').rstrip()
print("p-tex = ", plainText)

# รับค่า ciphertext (hex) จากเซิร์ฟเวอร์
cipherText_hex = r.recvline().decode('utf-8')
print("c-tex = ", cipherText_hex)

# รับค่า IV จากเซิร์ฟเวอร์
IV = r.recvline().decode('utf-8')
print("IV = ", IV)

# อ่านบรรทัดเพิ่มเติมจากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8')
print(response)

# เรียกใช้ฟังก์ชัน modify_cipher เพื่อสร้าง ciphertext ใหม่
modifyCipher = modify_cipher(plainText, cipherText_hex)
print("mod = ", modifyCipher)

# ส่ง ciphertext ใหม่และ IV กลับไปยังเซิร์ฟเวอร์
r.sendline(modifyCipher)
r.sendline(IV)

# รับและแสดงผลลัพธ์จากเซิร์ฟเวอร์
flag = r.recvline().decode('utf-8')
print(flag)
