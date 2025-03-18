from pwn import remote 
from Crypto.Util.strxor import strxor 
from binascii import unhexlify 
 
# ตั้งค่าเซิร์ฟเวอร์ที่ต้องเชื่อมต่อ
host = '172.26.201.109' 
port = 2222 
r = remote(host, port) 

# ส่งค่า '2' เพื่อเลือกข้อที่ 2
r.sendline(b'2') 

# รับและแสดงค่าของโจทย์ Q2
r.recvuntil(b'Q2: ') 
Q2 = r.recvline().decode('utf-8').strip() 
print(f"Q2: {Q2}") 

# รับและแสดงค่า Ciphertext ตัวที่ 1 (C1)
r.recvuntil(b'C1: ') 
C1 = r.recvline().decode('utf-8').strip() 
print(f"C1: {C1}") 

# รับและแสดงค่า Ciphertext ตัวที่ 2 (C2)
r.recvuntil(b'C2: ') 
C2 = r.recvline().decode('utf-8').strip() 
print(f"C2: {C2}") 

# รับและแสดงค่า Plaintext ตัวที่ 1 (P1)
r.recvuntil(b'P1: ') 
P1 = r.recvline().decode('utf-8').strip() 
print(f"P1: {P1}") 

# แปลงค่าต่าง ๆ เป็น bytes
P1_bytes = P1.encode()  # แปลง P1 เป็น bytes
C1_bytes = unhexlify(C1)  # แปลง C1 จาก hex เป็น bytes
C2_bytes = unhexlify(C2)  # แปลง C2 จาก hex เป็น bytes

# ตรวจสอบว่าความยาวของ C1 และ C2 เท่ากันหรือไม่ (ถ้าไม่เท่ากันให้หยุดทำงาน)
assert len(C1_bytes) == len(C2_bytes), "Error: C1 and C2 lengths do not match!"

# คำนวณค่า Key-stream โดย XOR ระหว่าง C1 และ C2
C1_C2_xor = strxor(C1_bytes, C2_bytes)

# คำนวณค่า P2 โดย XOR ระหว่าง P1 กับ Key-stream ที่หาได้
P2_bytes = strxor(P1_bytes, C1_C2_xor) 

# แปลงค่า P2 เป็นข้อความ และป้องกันการเกิด UnicodeDecodeError
P2 = P2_bytes.decode('utf-8', errors='ignore') 

# แสดงค่าของ P2 ที่กู้คืนมาได้
print(f"Recovered second plaintext: {P2}") 

# รอรับเครื่องหมาย `$` ก่อนส่งค่า P2 กลับไปที่เซิร์ฟเวอร์
r.recvuntil(b'$ ') 
r.sendline(P2.encode()) 

# รับและแสดงผลลัพธ์ (เช่น Flag) ที่เซิร์ฟเวอร์ส่งกลับมา
flag = r.recvline().decode('utf-8').strip()
print(flag) 

# ปิดการเชื่อมต่อกับเซิร์ฟเวอร์
r.close()
