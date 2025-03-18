from pwn import *  # นำเข้าไลบรารี pwn สำหรับการเชื่อมต่อกับเซิร์ฟเวอร์
from Crypto.Hash import MD5  # นำเข้าไลบรารี MD5 จาก PyCryptodome สำหรับการคำนวณแฮช
import re  # นำเข้าไลบรารี re สำหรับการใช้งาน Regular Expression

# กำหนดข้อมูลการเชื่อมต่อกับเซิร์ฟเวอร์
host = '0.tcp.ap.ngrok.io'  # ที่อยู่เซิร์ฟเวอร์
port = 16224  # พอร์ตเซิร์ฟเวอร์
r = remote(host, port)  # เชื่อมต่อกับเซิร์ฟเวอร์ผ่าน remote

# รับข้อมูลจากเซิร์ฟเวอร์จนกว่าจะถึงสัญลักษณ์ '$ '
chal_byte = r.recvuntil(b'$ ')
chal_str = chal_byte.decode('utf-8').strip()  # แปลงข้อมูลที่รับมาเป็น string และตัดช่องว่างส่วนเกิน
print(f"Received: {chal_str}")  # แสดงข้อความที่ได้รับจากเซิร์ฟเวอร์

# ส่งคำสั่ง '2' ไปยังเซิร์ฟเวอร์
print('2')
r.sendline(b'2')  # ส่งคำสั่ง '2' ไปยังเซิร์ฟเวอร์ (ตามคำแนะนำของ challenge)

# รับคำถามจากเซิร์ฟเวอร์
question = r.recvuntil(b"$").decode().strip()  # รับคำถามจนถึงเครื่องหมาย '$'
print(f"Received question:\n{question}")  # แสดงคำถามที่ได้รับจากเซิร์ฟเวอร์

# ฟังก์ชันสำหรับคำนวณ MD5 Hash ของข้อความและส่งคืนแฮช 5 ตัวแรก
def oHash(message):
    message = str.encode(message)  # แปลงข้อความเป็น byte string
    h = MD5.new(message)  # สร้าง MD5 hash object
    return h.hexdigest()[:5]  # คืนค่าแฮช 5 ตัวแรกจากการคำนวณ

# ใช้ Regular Expression เพื่อค้นหาค่า Hash ที่ต้องการจากคำถาม
target_hash_match = re.search(r'[a-f0-9]{5}', question)  # ค้นหาตัวเลขฐาน 16 ที่มีความยาว 5 ตัว
if target_hash_match:
    target_hash = target_hash_match.group(0)  # ดึงค่าแฮชที่พบจากคำถาม
    print(f"Target hash: {target_hash}")  # แสดง target hash ที่ต้องการ
else:
    print("Could not find the target hash")  # ถ้าไม่พบแฮชในคำถาม
    r.close()  # ปิดการเชื่อมต่อ
    exit()  # ออกจากโปรแกรม

# เริ่มทำการ brute-force ค้นหาพาสเวิร์ดที่ตรงกับแฮชที่ต้องการ
found = False  # ตัวแปรสำหรับเช็คว่าเจอพาสเวิร์ดหรือยัง
for i in range(1000000):  # ลองทุกพาสเวิร์ดจาก 000000 ถึง 999999
    password = f"{i:06}"  # สร้างพาสเวิร์ดที่มีความยาว 6 หลัก
    if oHash(password) == target_hash:  # ตรวจสอบว่าแฮชของพาสเวิร์ดตรงกับ target hash หรือไม่
        print(f"Password found: {password}")  # แสดงพาสเวิร์ดที่พบ
        r.sendline(password.encode('utf-8'))  # ส่งพาสเวิร์ดที่พบไปยังเซิร์ฟเวอร์
        found = True  # ตั้งค่า found เป็น True
        r.interactive()  # เปิด interactive mode เพื่อให้ผู้ใช้สามารถโต้ตอบกับเซิร์ฟเวอร์ได้
        break  # หยุดการวนลูปเมื่อเจอพาสเวิร์ดที่ตรงกับแฮช

if not found:  # ถ้าไม่พบพาสเวิร์ดที่ตรงกับแฮช
    print("Password not found")  # แสดงข้อความว่าไม่พบพาสเวิร์ด

r.close()  # ปิดการเชื่อมต่อกับเซิร์ฟเวอร์
