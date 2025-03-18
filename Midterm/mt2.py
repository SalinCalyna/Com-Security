from pwn import *  
from Crypto.Util.Padding import pad
from Crypto.Cipher import DES

host = '172.26.125.102'  
port = 9876  
r = remote(host, port) 

chal_byte = r.recvuntil(b'$ ')  
chal_str = chal_byte.decode('utf-8')[:-3]  
print(chal_str)  

print('2') 
r.sendline(b'2')  

response = r.recvline().decode('utf-8')

question = r.recvline().decode('utf-8')
print(question)

def double_encrypt(m, iv):
    m= str.encode(m)
    msg = pad(m, DES.block_size)

    Ciper1 =DES.new(key1, DES.MODE_CFB, iv)
    enc_msg = Ciper2.encrypt(msg)

    Ciper2 =DES.new(Key2,DES.MODE_CBC,iv)
    enc_msg2 = Ciper2.encrypt(enc_msg)
    return enc_msg2



plaintext = pad(b"Good luck!", 6)  
print(plaintext)  

encodes = {}
decodes = {}


for key in tqdm(range(1000000), desc="Yehhh i got the flag"):
    key = pad(f'{key:06}'.encode(), 8)  # เติม padding ให้กับคีย์ให้มีความยาว 8 ไบต์
    DESkey = DES.new(key, DES.MODE_ECB)  # สร้าง DES cipher ด้วยคีย์ที่กำหนด

    enc_p = DESkey.encrypt(plaintext)  # เข้ารหัส plaintext ด้วยคีย์นี้
    encodes[enc_p] = key  # เก็บผลลัพธ์การเข้ารหัสใน dictionary

    dec_c = DESkey.decrypt(Ciper1)  # ถอดรหัส ciphertext ด้วยคีย์นี้
    decodes[dec_c] = key  # เก็บผลลัพธ์การถอดรหัสใน dictionary

print("Finding intersection...")

for same_inter_text in set(encodes.keys()).intersection(set(decodes.keys())):
    k1 = encodes[same_inter_text]  # คีย์ที่ใช้ในการเข้ารหัส
    k2 = decodes[same_inter_text]  # คีย์ที่ใช้ในการถอดรหัส
    print(f"Keys found: K1 = {k1}, K2 = {k2}")

    DESkey1 = DES.new(k1, DES.MODE_CFB)  # สร้าง DES cipher ด้วยคีย์แรก
    DESkey2 = DES.new(k2, DES.MODE_CBC)  # สร้าง DES cipher ด้วยคีย์ที่สอง
    test_intermediate = DESkey1.encrypt(plaintext)  # ทดสอบการเข้ารหัสครั้งแรกด้วยคีย์ K1
    test_cipher = DESkey2.encrypt(test_intermediate)  # ทดสอบการเข้ารหัสครั้งที่สองด้วยคีย์ K2

    # ตรวจสอบว่า ciphertext ที่ได้จากการเข้ารหัสสองครั้งตรงกับ ciphertext ที่ได้รับจากเซิร์ฟเวอร์
    if test_cipher == ciphertext:
        print("Keys validated successfully.")  # ถ้าตรงกัน แสดงว่าคีย์ถูกต้อง
        break  # หยุดการวนลูปเมื่อเจอคีย์ที่ถูกต้อง

# ถอดรหัส flag ด้วยคีย์ที่พบ
DESkey1 = DES.new(k1, DES.MODE_CFB)  # สร้าง DES cipher ด้วยคีย์แรก
DESkey2 = DES.new(k2, DES.MODE_CBC)  # สร้าง DES cipher ด้วยคีย์ที่สอง
inter_flag = DESkey2.decrypt(flag_bytes)  # ถอดรหัส flag ครั้งแรกด้วยคีย์ K2
print(f"Intermediate flag: {inter_flag}")  # แสดงค่า intermediate flag


response = r.recvline().decode('utf-8')  
print(response) 

r.close()  


