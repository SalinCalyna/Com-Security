from Crypto.Cipher import DES
from tqdm import tqdm # ใช้สำหรับแสดง progress bar ตอน brute-force หาคีย์
from Crypto.Util.Padding import pad, unpad
from pwn import *

# กำหนดข้อมูลการเชื่อมต่อกับเซิร์ฟเวอร์
host = '172.26.201.109'
port = 2222
r = remote(host, port)  # เชื่อมต่อกับเซิร์ฟเวอร์ผ่าน remote

# รับข้อมูลจากเซิร์ฟเวอร์จนกว่าจะถึงสัญลักษณ์ '$'
chal_bytes = r.recvuntil(b'$')
chal_str = chal_bytes.decode('utf-8')
print(chal_str)  # แสดงข้อมูลที่ได้รับจากเซิร์ฟเวอร์

r.sendline(str(5))  # ส่งคำตอบ '5' ไปยังเซิร์ฟเวอร์ (อาจเป็นการดำเนินการในขั้นตอนถัดไป)

# รับข้อมูลที่เหลือจากเซิร์ฟเวอร์
chal_bytes = r.recvall()
chal_str = chal_bytes.decode('utf-8')
print(chal_str)  # แสดงข้อมูลที่ได้รับทั้งหมดจากเซิร์ฟเวอร์

# ดึงค่า flag จากข้อมูลที่ได้รับ
flag = chal_bytes.split(b'\n')[1].split(b'see generate_key())')[0].strip()
print(flag.decode('utf-8'))  # แสดง flag ที่ดึงมา
flag_bytes = bytes.fromhex(flag.decode('utf-8'))  # แปลง flag จาก hexadecimal เป็น bytes
print("Cipher_flag =", flag_bytes)  # แสดงค่าของ flag ในรูปแบบ bytes

# ดึงค่า ciphertext จากข้อมูลที่ได้รับ
ciphertext = chal_bytes.split(b'same keys')[1].split(b'\n\n')[0].strip().decode('utf-8')
print("Cipher_goodluck =", ciphertext)  # แสดง ciphertext
ciphertext = bytes.fromhex(ciphertext)  # แปลง ciphertext จาก hexadecimal เป็น bytes

# กำหนดค่า plaintext ที่ใช้ทดสอบ
plaintext = pad(b"Good luck!", 8)  # เติม padding ให้กับ plaintext เพื่อให้มีขนาดเป็นพหุคูณของ 8 (ขนาดบล็อกของ DES)
print(plaintext)  # แสดง plaintext ที่เติม padding

# กำหนด dictionary สำหรับเก็บผลลัพธ์การเข้ารหัสและถอดรหัส
encodes = {}
decodes = {}

# ลูป brute-force หาคีย์ที่ถูกต้อง (จะลองคีย์ทั้งหมด 1 ล้านค่าจาก 000000 ถึง 999999)
for key in tqdm(range(1000000), desc="Yehhh i got the flag"):
    key = pad(f'{key:06}'.encode(), 8)  # เติม padding ให้กับคีย์ให้มีความยาว 8 ไบต์
    DESkey = DES.new(key, DES.MODE_ECB)  # สร้าง DES cipher ด้วยคีย์ที่กำหนด

    enc_p = DESkey.encrypt(plaintext)  # เข้ารหัส plaintext ด้วยคีย์นี้
    encodes[enc_p] = key  # เก็บผลลัพธ์การเข้ารหัสใน dictionary

    dec_c = DESkey.decrypt(ciphertext)  # ถอดรหัส ciphertext ด้วยคีย์นี้
    decodes[dec_c] = key  # เก็บผลลัพธ์การถอดรหัสใน dictionary

# หาคีย์ที่ถูกต้องโดยการหาค่าที่เหมือนกันในผลลัพธ์ของการเข้ารหัสและถอดรหัส
print("Finding intersection...")

for same_inter_text in set(encodes.keys()).intersection(set(decodes.keys())):
    k1 = encodes[same_inter_text]  # คีย์ที่ใช้ในการเข้ารหัส
    k2 = decodes[same_inter_text]  # คีย์ที่ใช้ในการถอดรหัส
    print(f"Keys found: K1 = {k1}, K2 = {k2}")

    DESkey1 = DES.new(k1, DES.MODE_ECB)  # สร้าง DES cipher ด้วยคีย์แรก
    DESkey2 = DES.new(k2, DES.MODE_ECB)  # สร้าง DES cipher ด้วยคีย์ที่สอง
    test_intermediate = DESkey1.encrypt(plaintext)  # ทดสอบการเข้ารหัสครั้งแรกด้วยคีย์ K1
    test_cipher = DESkey2.encrypt(test_intermediate)  # ทดสอบการเข้ารหัสครั้งที่สองด้วยคีย์ K2

    # ตรวจสอบว่า ciphertext ที่ได้จากการเข้ารหัสสองครั้งตรงกับ ciphertext ที่ได้รับจากเซิร์ฟเวอร์
    if test_cipher == ciphertext:
        print("Keys validated successfully.")  # ถ้าตรงกัน แสดงว่าคีย์ถูกต้อง
        break  # หยุดการวนลูปเมื่อเจอคีย์ที่ถูกต้อง

# ถอดรหัส flag ด้วยคีย์ที่พบ
DESkey1 = DES.new(k1, DES.MODE_ECB)  # สร้าง DES cipher ด้วยคีย์แรก
DESkey2 = DES.new(k2, DES.MODE_ECB)  # สร้าง DES cipher ด้วยคีย์ที่สอง
inter_flag = DESkey2.decrypt(flag_bytes)  # ถอดรหัส flag ครั้งแรกด้วยคีย์ K2
print(f"Intermediate flag: {inter_flag}")  # แสดงค่า intermediate flag

# ถอดรหัสครั้งสุดท้ายโดยใช้คีย์ K1 และลบ padding
try:
    flag = unpad(DESkey1.decrypt(inter_flag), 8)  # ใช้คีย์ K1 ถอดรหัสครั้งสุดท้ายและลบ padding
    print(f"Decrypted Flag: {flag.decode('utf-8')}")  # แสดงผล flag ที่ถอดรหัสแล้ว
except ValueError:
    print("Decryption failed: Padding is incorrect.")  # ถ้าการถอดรหัสผิดพลาดจาก padding
