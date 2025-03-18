from pwn import *  # นำเข้าไลบรารี pwn สำหรับเชื่อมต่อกับเซิร์ฟเวอร์
from hashlib import md5  # นำเข้า md5 จากไลบรารี hashlib สำหรับคำนวณ MD5 Hash
import random  # นำเข้าไลบรารี random สำหรับการสุ่มค่าต่าง ๆ
import string  # นำเข้าไลบรารี string สำหรับการใช้งานอักษรและตัวเลข

# กำหนดข้อมูลการเชื่อมต่อกับเซิร์ฟเวอร์
host = '0.tcp.ap.ngrok.io'  # ที่อยู่ของเซิร์ฟเวอร์
port = 16224  # พอร์ตที่ใช้เชื่อมต่อ
r = remote(host, port)  # เชื่อมต่อกับเซิร์ฟเวอร์ผ่าน pwn

# รับข้อมูลจากเซิร์ฟเวอร์จนกว่าจะถึง '$ '
chal_str = r.recvuntil(b'$ ').decode('utf-8').strip()  # รับคำท้าและแปลงเป็น string
print(f"Received: {chal_str}")  # แสดงข้อความที่ได้รับจากเซิร์ฟเวอร์

# ส่งคำสั่ง '3' ไปยังเซิร์ฟเวอร์
r.sendline(b'3')

# รับคำถามจากเซิร์ฟเวอร์
question = r.recvuntil(b"$").decode().strip()  # รับคำถามจากเซิร์ฟเวอร์
print(f"Received question:\n{question}")  # แสดงคำถามที่ได้รับ

# ฟังก์ชันคำนวณ MD5 Hash ของข้อความและส่งคืน 10 ตัวแรกของแฮช
def oHashPlus(message):
    return md5(message.encode()).hexdigest()[:10]  # ใช้ MD5 และตัดแฮช 10 ตัวแรก

# ฟังก์ชันสุ่มชื่อผู้ใช้ที่มีความยาวตามที่กำหนด
def random_username(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))  # สุ่มชื่อผู้ใช้จากตัวอักษรและตัวเลข

# ฟังก์ชันหา collision ของแฮช
def find_collision():
    seen_hashes = {}  # สร้าง dictionary สำหรับเก็บแฮชที่พบแล้ว
    attempts = 0  # ตัวแปรนับจำนวนการพยายาม
    while True:
        username = random_username()  # สุ่มชื่อผู้ใช้
        hash_value = oHashPlus(username)  # คำนวณแฮชของชื่อผู้ใช้
        if hash_value in seen_hashes:  # ถ้าแฮชนี้เคยพบแล้ว
            print(f"Collision found after {attempts} attempts!")  # แสดงผลลัพธ์เมื่อพบ collision
            return seen_hashes[hash_value], username  # คืนค่าผลลัพธ์เป็นชื่อผู้ใช้ที่มี collision
        seen_hashes[hash_value] = username  # เก็บแฮชและชื่อผู้ใช้ที่พบ
        attempts += 1  # เพิ่มจำนวนการพยายาม
        if attempts % 1000 == 0:  # ถ้าพยายามครบ 1000 ครั้ง
            print(f"Attempts: {attempts}, Hashes: {len(seen_hashes)}")  # แสดงจำนวนการพยายามและจำนวนแฮชที่พบ

# เรียกใช้งานฟังก์ชันหา collision
username1, username2 = find_collision()

# แสดงผลลัพธ์เมื่อพบ collision
print(f"Collision found!")
print(f"Username 1: {username1}, Hash: {oHashPlus(username1)}")  # แสดงชื่อผู้ใช้และแฮชของมัน
print(f"Username 2: {username2}, Hash: {oHashPlus(username2)}")  # แสดงชื่อผู้ใช้และแฮชของมัน

# ส่งชื่อผู้ใช้ทั้งสองไปยังเซิร์ฟเวอร์
r.sendline(username1)
r.sendline(username2)

# รับและแสดงผลลัพธ์จากเซิร์ฟเวอร์
response = r.recvall().decode()  # รับข้อความจากเซิร์ฟเวอร์จนหมด
print(f"Server response: {response}")  # แสดงผลลัพธ์ที่ได้รับจากเซิร์ฟเวอร์

# ปิดการเชื่อมต่อกับเซิร์ฟเวอร์
r.close()
