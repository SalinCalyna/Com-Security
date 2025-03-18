from pwn import *  # นำเข้าไลบรารีสำหรับการเชื่อมต่อกับเซิร์ฟเวอร์ (pwnlib)
from Crypto.Hash import SHA256  # นำเข้าไลบรารี SHA256 สำหรับการคำนวณแฮช

# กำหนดข้อมูลการเชื่อมต่อกับเซิร์ฟเวอร์
host = '0.tcp.ap.ngrok.io'  # ที่อยู่เซิร์ฟเวอร์
port = 16224  # พอร์ตเซิร์ฟเวอร์
r = remote(host, port)  # เชื่อมต่อกับเซิร์ฟเวอร์ผ่าน remote

# รับข้อมูลจากเซิร์ฟเวอร์จนกว่าจะถึงสัญลักษณ์ "$ "
chal_byte = r.recvuntil(b'$ ')
chal_str = chal_byte.decode('utf-8').strip()  # แปลงข้อมูลที่รับมาเป็น string และตัดช่องว่างส่วนเกิน
print(f"Received: {chal_str}")  # แสดงข้อความที่ได้รับจากเซิร์ฟเวอร์

# ส่งคำสั่ง '1' ไปยังเซิร์ฟเวอร์
print('1')  
r.sendline(b'1')  # ส่งคำสั่ง '1' ไปยังเซิร์ฟเวอร์

# รับคำถามจากเซิร์ฟเวอร์
question = r.recvuntil(b"$").decode().strip()  # รับคำถามจนถึงเครื่องหมาย '$'
print(f"Received question:\n{question}")  # แสดงคำถามที่ได้รับจากเซิร์ฟเวอร์

# แยกคำถามออกเป็นบรรทัด ๆ
lines = question.split("\n")

# สร้างรายการสำหรับเก็บ UUID และ Hash
uuids = []
hashes = []

# วนลูปตรวจสอบแต่ละบรรทัดในคำถาม
for line in lines:
    if "UUID:" in line:  # ถ้าบรรทัดนี้มี UUID
        uuids.append(line.split(":")[1].strip())  # แยก UUID และเก็บในรายการ uuids
    elif "Hash(UUID):" in line:  # ถ้าบรรทัดนี้มี Hash(UUID)
        hashes.append(line.split(":")[1].strip())  # แยก Hash และเก็บในรายการ hashes

# สร้างรายการเพื่อเก็บผลลัพธ์
results = []

# วนลูปตรวจสอบ UUID และ Hash ทั้ง 20 ตัว
for i in range(20):  
    uuid = uuids[i]  # ดึงค่า UUID จากรายการ
    expected_hash = hashes[i]  # ดึงค่า Hash ที่คาดหวังจากรายการ

    h = SHA256.new()  # สร้าง SHA256 object
    h.update(uuid.encode())  # อัปเดต SHA256 ด้วย UUID
    computed_hash = h.hexdigest()  # คำนวณแฮชของ UUID
    
    # เปรียบเทียบแฮชที่คำนวณได้กับแฮชที่คาดหวัง
    if computed_hash == expected_hash:
        results.append('Y')  # ถ้าแฮชตรงกัน ให้เพิ่ม 'Y' ในผลลัพธ์
    else:
        results.append('N')  # ถ้าแฮชไม่ตรงกัน ให้เพิ่ม 'N' ในผลลัพธ์

# รวมผลลัพธ์เป็นสตริง
result_str = ''.join(results)  
print("Result:", result_str)  # แสดงผลลัพธ์ที่คำนวณได้

# ส่งผลลัพธ์กลับไปยังเซิร์ฟเวอร์
r.sendline(result_str.encode())  # ส่งผลลัพธ์ที่คำนวณได้กลับไปยังเซิร์ฟเวอร์
print("[DEBUG] Sent result to server")  # แสดงข้อความว่าได้ส่งผลลัพธ์ไปแล้ว

r.close()  # ปิดการเชื่อมต่อกับเซิร์ฟเวอร์
