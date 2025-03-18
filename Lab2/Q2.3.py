from pwn import *
from Crypto.Cipher import AES
from tqdm import tqdm

# ฟังก์ชันตรวจสอบว่ามีบล็อกของ ciphertext ซ้ำกันหรือไม่ (ใช้ตรวจสอบการโจมตี ECB mode)
def check_ciphertext(ciphertext1):
    block_size = 16  # ขนาดของบล็อกใน AES
    blocks = [ciphertext1[i:i+block_size] for i in range(0, len(ciphertext1), block_size)]
    
    # แสดงค่าแต่ละบล็อกของ ciphertext
    print("Ciphertext blocks:")
    for idx, block in enumerate(blocks):
        print(f"Block {idx}: {block.hex()}")
    
    # เปรียบเทียบแต่ละบล็อกเพื่อดูว่ามีบล็อกที่ซ้ำกันหรือไม่
    for i in range(len(blocks)):
        for j in range(i + 1, len(blocks)):
            if blocks[i] == blocks[j]:
                return True  # พบว่ามีบล็อกซ้ำกัน
    
    return False  # ไม่มีบล็อกซ้ำกัน

# ตั้งค่าที่อยู่ของเซิร์ฟเวอร์
host = "172.26.201.109"
port = 2222
r = remote(host, port)  # เชื่อมต่อไปยังเซิร์ฟเวอร์

# รับและแสดงข้อความจากเซิร์ฟเวอร์
message = r.recvuntil(b'$')
print(message.decode('utf-8'))

# ส่งตัวเลือกที่ 3 ไปยังเซิร์ฟเวอร์
r.sendline(str(3))

# รับและแสดงคำถามจากเซิร์ฟเวอร์
q3 = r.recvuntil(b'$')
print(q3.decode('utf-8'))

# สร้างข้อมูลเริ่มต้นที่มี 14 ไบต์เป็นศูนย์
temp_text = b'\00' * 14  
r.sendline(temp_text.hex())  # ส่งค่า temp_text เป็น hex ไปยังเซิร์ฟเวอร์

# รับ ciphertext ที่เข้ารหัสกลับมาและแสดงผล
ciphertext_main = r.recvuntil(b'$').split(b'\n')[0].strip()
print("ciphertext:", ciphertext_main.decode('utf-8'))

# กำหนดค่าไบต์เริ่มต้นที่ใช้ทดสอบ
byte_value1_str = '00'
byte_value2_str = '00'

# ตัวแปรสำหรับบันทึกว่าพบค่าที่ทำให้เกิดบล็อกซ้ำหรือไม่
found_combination = False

# วนลูปทดสอบค่าตั้งแต่ 00-FF สำหรับ byte1 และ byte2
for value1 in tqdm(range(256), desc="Testing byte1 values", unit="byte1"):
    byte_value1 = format(value1, '02X')  # แปลงค่าเป็นรูปแบบ 2 หลัก เช่น 0 -> 00, 5 -> 05
    for value2 in tqdm(range(256), desc="Testing byte2 values", unit="byte2"):
        byte_value2 = format(value2, '02X')
        byte_value1_str = byte_value1
        byte_value2_str = byte_value2
        
        # สร้างข้อความใหม่โดยเพิ่มค่า byte ที่ทดสอบเข้าไป
        new_text = temp_text + bytes.fromhex(byte_value1_str) + bytes.fromhex(byte_value2_str) + temp_text
        print(new_text.hex())

        # ส่งค่าที่ทดสอบไปยังเซิร์ฟเวอร์
        r.sendline(new_text.hex())

        # รับ ciphertext ใหม่จากเซิร์ฟเวอร์
        cipher_text = r.recvuntil(b'$').split(b'\n')[0].strip()

        # ตรวจสอบว่ามีบล็อกที่ซ้ำกันหรือไม่
        if check_ciphertext(cipher_text):
            found_combination = True
            break  # ออกจากลูปถ้าพบค่าที่ต้องการ

    if found_combination:
        break  # ออกจากลูปหลักถ้าพบค่าที่ต้องการ

# ถ้าพบค่าที่ทำให้เกิดบล็อกซ้ำกัน
if found_combination:
    print("We found it!")
    print("Byte 1:", byte_value1_str)
    print("Byte 2:", byte_value2_str)

    # ส่งคำสั่ง 'c' ไปยังเซิร์ฟเวอร์
    r.sendline("c")

    # รับและแสดงข้อมูลจากเซิร์ฟเวอร์
    data1 = r.recvline().decode("utf-8")
    text1 = byte_value1_str + byte_value2_str
    text1 = bytes.fromhex(text1)
    print(text1.hex())

    # ส่งค่าที่พบไปยังเซิร์ฟเวอร์
    r.sendline(text1.hex())

    # รับและแสดงผลลัพธ์จากเซิร์ฟเวอร์
    data1 = r.recvline().decode("utf-8")
    print(data1)

else:
    print("No matching combination found.")  # ถ้าไม่พบค่าที่ทำให้เกิดบล็อกซ้ำกัน

# ปิดการเชื่อมต่อกับเซิร์ฟเวอร์
r.close()
