from Crypto.Cipher import DES
from tqdm import tqdm # Brute-force หา key ที่ถูกต้อง
from Crypto.Util.Padding import pad, unpad
from pwn import *
 
host = '172.26.201.109'
port = 2222
r = remote(host, port)
 
chal_bytes = r.recvuntil(b'$')
chal_str = chal_bytes.decode('utf-8')
print(chal_str)
 
r.sendline(str(5))
 
chal_bytes = r.recvall()
chal_str = chal_bytes.decode('utf-8')
print(chal_str)

#ดึงค่า Flag ออกจากข้อความ
flag = chal_bytes.split(b'\n')[1].split(b'see generate_key())')[0].strip()
print(flag.decode('utf-8'))
flag_bytes = bytes.fromhex(flag.decode('utf-8'))
print("Cipher_flag =", flag_bytes)

# ดึงค่า Ciphertext ออกจากข้อความ
ciphertext = chal_bytes.split(b'same keys')[1].split(b'\n\n')[0].strip().decode('utf-8')
print("Cipher_goodluck =", ciphertext)
ciphertext = bytes.fromhex(ciphertext)

#กำหนดค่า Plaintext ที่ใช้ทดสอบ
plaintext = pad(b"Good luck!", 8)  
print(plaintext)
 
encodes = {}
decodes = {}
for key in tqdm(range(1000000), desc="Yehhh i got the flag"):
    key = pad(f'{key:06}'.encode(), 8)
    DESkey = DES.new(key, DES.MODE_ECB)
 
    enc_p = DESkey.encrypt(plaintext)#เข้ารหัส (plaintext) ด้วยทุกๆ คีย์ K1 และเก็บผลลัพธ์ไว้
    encodes[enc_p] = key
 
    dec_c = DESkey.decrypt(ciphertext)#ถอดรหัส (ciphertext) ด้วยทุกๆ คีย์ K2 และเก็บผลลัพธ์ไว้
    decodes[dec_c] = key
 
print("Finding intersection...")
 
#หา k1,k2 ที่ถุกต้อง
for same_inter_text in set(encodes.keys()).intersection(set(decodes.keys())):
    k1 = encodes[same_inter_text]
    k2 = decodes[same_inter_text]
    print(f"Keys found: K1 = {k1}, K2 = {k2}")
 

    DESkey1 = DES.new(k1, DES.MODE_ECB)
    DESkey2 = DES.new(k2, DES.MODE_ECB)
    test_intermediate = DESkey1.encrypt(plaintext) #ทดสอบเข้ารหัสครั้ง1
    test_cipher = DESkey2.encrypt(test_intermediate) #ทดสอบเข้ารหัสครั้ง2
 
    if test_cipher == ciphertext: #ตรวจสอบว่าตรงกับค่า ciphertext ไม่
        print("Keys validated successfully.")
        break
 
# ฟังก์ชันสำหรับถอดรหัส Flag
DESkey1 = DES.new(k1, DES.MODE_ECB) 
DESkey2 = DES.new(k2, DES.MODE_ECB) 
inter_flag = DESkey2.decrypt(flag_bytes)#ถอดรหัส flag ครั้งแรก (ย้อนกลับกระบวนการ 2DES)
print(f"Intermediate flag: {inter_flag}")#ถ้าพบค่าเดียวกัน → คีย์ K1 และ K2 ถูกต้อง
 
try:
    flag = unpad(DESkey1.decrypt(inter_flag), 8) #ใช้ K1 ถอดรหัสรอบสุดท้าย และลบ padding
    print(f"Decrypted Flag: {flag.decode('utf-8')}")
except ValueError:
    print("Decryption failed: Padding is incorrect.")
 
