from pwn import *  # นำเข้า pwntools สำหรับการเชื่อมต่อกับเซิร์ฟเวอร์

# กำหนด IP และพอร์ตของเซิร์ฟเวอร์
host = '172.26.201.109'
port = 1111

# สร้างการเชื่อมต่อไปยังเซิร์ฟเวอร์
r = remote(host, port)

# ฟังก์ชันสำหรับเข้ารหัส Vigenère Cipher
def encrypt(plainText, key):
    answer = ""
    for p, k in zip(plainText, key):  # จับคู่ตัวอักษรจาก plainText และ key
        plain_val = ord(p) - 97  # แปลงตัวอักษรเป็นค่าตัวเลข (a = 0, b = 1, ... , z = 25)
        key_val = ord(k) - 97  # แปลงตัวอักษรของ key เป็นค่าตัวเลข
        print(f"plainText = {plain_val}, Key = {key_val}")
        
        x = (plain_val + key_val) % 26  # คำนวณค่ารหัสตามหลัก Vigenère
        print(f"Calculated x (plain_val + key_val) % 26 = {x}")
        
        encrypt_char = chr(x + 97)  # แปลงค่ากลับเป็นตัวอักษร
        answer += encrypt_char  # รวมข้อความที่เข้ารหัสแล้ว
    return answer

# ฟังก์ชันสำหรับถอดรหัส Vigenère Cipher
def decrypt(cipherText, key):
    answer = ""
    for c, k in zip(cipherText, key):  # จับคู่ตัวอักษรจาก cipherText และ key
        cipher_val = ord(c) - 97  # แปลงตัวอักษรเข้ารหัสเป็นค่าตัวเลข
        key_val = ord(k) - 97  # แปลงตัวอักษรของ key เป็นค่าตัวเลข
        print(f"cipherText = {cipher_val}, Key = {key_val}")
        
        x = (cipher_val - key_val + 26) % 26  # คำนวณการถอดรหัส
        print(f"Calculated x (cipher_val - key_val + 26) % 26 = {x}")
        
        decrypt_char = chr(x + 97)  # แปลงค่ากลับเป็นตัวอักษร
        answer += decrypt_char  # รวมข้อความที่ถอดรหัสแล้ว
    return answer

# รับข้อความต้อนรับจากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8')

# ส่งตัวเลือก '5' เพื่อเลือกโจทย์เกี่ยวกับ Vigenère Cipher
r.sendline(b'5')
print(response.strip())

# รับคำถามจากเซิร์ฟเวอร์
question = r.recvline().decode('utf-8')
print(question.strip())

# ข้ามข้อมูลที่ไม่ได้ใช้งาน (9 บรรทัด)
r.recvlines(9)

# รับ plaintext ที่ต้องเข้ารหัส
response = r.recvline().decode('utf-8')
plainText = response.split(':')[1].strip()  # ดึงข้อความต้นฉบับ

# รับ key ที่ใช้ในการเข้ารหัส
response = r.recvline().decode('utf-8')
key = response.split(':')[1].strip()  # ดึง key

# ทำการเข้ารหัส
cipherText = encrypt(plainText, key)
print(f"CipherText: {cipherText}")

# ส่งข้อความที่เข้ารหัสกลับไปยังเซิร์ฟเวอร์
r.sendline(cipherText.encode('utf-8'))

# รับข้อความตอบกลับจากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8').strip()
print(response.strip())

# รับ ciphertext ที่ต้องถอดรหัส
response = r.recvline().decode('utf-8').strip()
cipherText = response.split(':')[1].strip()  # ดึงข้อความเข้ารหัส

# รับ key ที่ใช้ในการถอดรหัส
response = r.recvline().decode('utf-8').strip()
key = response.split(':')[1].strip()  # ดึง key

# ทำการถอดรหัส
decryptedText = decrypt(cipherText, key)
print(f"Decrypted PlainText: {decryptedText}")

# ส่งข้อความที่ถอดรหัสกลับไปยังเซิร์ฟเวอร์
r.sendline(decryptedText.encode('utf-8'))

# รับข้อความตอบกลับสุดท้ายจากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8').strip()
print(response.strip())
