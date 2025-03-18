from pwn import *  # ใช้ pwntools สำหรับการเชื่อมต่อเครือข่าย

# ตั้งค่า host และ port ของเซิร์ฟเวอร์ที่ต้องการเชื่อมต่อ
host = '172.26.201.109'
port = 1111

# เชื่อมต่อไปยังเซิร์ฟเวอร์
r = remote(host, port)

# รับข้อมูลแรกจากเซิร์ฟเวอร์
chal_byte = r.recvuntil(b'$ ')  # รอรับข้อมูลจนถึงสัญลักษณ์ '$ '
chal_str = chal_byte.decode('utf-8').strip('$ ')  # แปลงเป็นสตริง และตัด '$ ' ออก
print(chal_str)

# ส่งค่า '2' เพื่อเลือกคำถาม
r.sendline(b'2')
Q2 = r.recvuntil(b'w:\n\n').decode('utf-8').strip()  # รับข้อมูลของโจทย์
print(Q2)

# รับอักขระที่ใช้เป็น key สำหรับเข้ารหัสและถอดรหัส
alp = r.recvline().decode('utf-8').strip()
print(alp)

# รับตัวอักษรลูกศร (ใช้ในคำอธิบาย แต่ไม่ใช้ในโค้ด)
Arrow1 = r.recvline().decode('utf-8').strip()
Arrow2 = r.recvline().decode('utf-8').strip()

# รับโค้ดที่ใช้แมพกับอักขระ
code = r.recvline().decode('utf-8').strip()
print(code)

# รับบรรทัดว่าง
blank = r.recvuntil(b'\n').decode('utf-8').strip()
print(blank)

# รับข้อความที่ถูกเข้ารหัส
e = r.recvuntil(b': ').decode('utf-8').strip()
c_text = r.recvline().decode('utf-8').strip()
print(e, c_text)

# สร้าง mapping สำหรับการเข้ารหัสและถอดรหัส
code_map = {alp[i]: code[i] for i in range(len(alp))}  # แปลงตัวอักษรเป็นรหัส
print(code_map)
code_map2 = {code[i]: alp[i] for i in range(len(alp))}  # แปลงรหัสกลับเป็นตัวอักษร
print(code_map2)

# ฟังก์ชันถอดรหัส
def decrypt(code_map, e_text):
    return ''.join(code_map.get(char, char) for char in e_text)  # ใช้ get() ป้องกัน KeyError

# ถอดรหัสข้อความที่ได้รับ
answer = decrypt(code_map, c_text)

# ส่งคำตอบที่ถอดรหัสแล้วกลับไปยังเซิร์ฟเวอร์
r.sendline(answer.encode('utf-8'))
e = r.recvuntil(b":").decode('utf-8').strip()
print(e, answer)

# รับข้อความที่ต้องเข้ารหัสกลับ
response = r.recvuntil(b": ").decode('utf-8').strip()
e_text = r.recvline().decode('utf-8').strip()
print(response, e_text)

# ฟังก์ชันเข้ารหัส
def encrypt(code_map2, e_text):
    return ''.join(code_map2.get(char, char) for char in e_text)  # ใช้ get() ป้องกัน KeyError

# เข้ารหัสข้อความที่ได้รับ
answer_r = encrypt(code_map2, e_text)

# ส่งข้อความที่เข้ารหัสกลับไปยังเซิร์ฟเวอร์
r.sendline(answer_r.encode('utf-8'))
e = r.recvuntil(b": ").decode('utf-8').strip()
print(e, answer_r)

# รับข้อความสุดท้าย
e = r.recvline().decode('utf-8').strip()
print(e)

# ปิดการเชื่อมต่อ
r.close()
