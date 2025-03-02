from pwn import *  

host = '172.26.201.109'  
port = 1111  

r = remote(host, port)  

# รับข้อมูลแรก
chal_byte = r.recvuntil(b'$ ')  
chal_str = chal_byte.decode('utf-8').strip('$ ')  
print(chal_str)  

r.sendline(b'2')  
Q2 = r.recvuntil(b'w:\n\n').decode('utf-8').strip()  
print(Q2)  

# รับอักขระที่ใช้เป็น key
alp = r.recvline().decode('utf-8').strip()  
print(alp)  

Arrow1 = r.recvline().decode('utf-8').strip()  
Arrow2 = r.recvline().decode('utf-8').strip()  

# รับโค้ดที่แมพกับอักขระ
code = r.recvline().decode('utf-8').strip()  
print(code)  

blank = r.recvuntil(b'\n').decode('utf-8').strip()  
print(blank)  
e = r.recvuntil(b': ').decode('utf-8').strip()  

# รับข้อความที่ถูกเข้ารหัส
c_text = r.recvline().decode('utf-8').strip()  
print(e, c_text)  

# สร้าง mapping สำหรับการถอดรหัสและเข้ารหัส
code_map = {alp[i]: code[i] for i in range(len(alp))} #rangeการลำดับจำนวนตัวเลข
print(code_map)  
code_map2 = {code[i]: alp[i] for i in range(len(alp))}  
print(code_map2) 

def decrypt(code_map, e_text):  
    return ''.join(code_map.get(char, char) for char in e_text)  # ป้องกัน KeyError

answer = decrypt(code_map, c_text)  

r.sendline(answer.encode('utf-8'))  
e = r.recvuntil(b":").decode('utf-8').strip()  
print(e, answer)  

# รับข้อความที่ต้องเข้ารหัสกลับ
response = r.recvuntil(b": ").decode('utf-8').strip()  
e_text = r.recvline().decode('utf-8').strip()  
print(response, e_text)  

def encrypt(code_map2, e_text):  
    return ''.join(code_map2.get(char, char) for char in e_text)  # ป้องกัน KeyError

answer_r = encrypt(code_map2, e_text)  

r.sendline(answer_r.encode('utf-8'))  
e = r.recvuntil(b": ").decode('utf-8').strip()  
print(e, answer_r)  

e = r.recvline().decode('utf-8').strip()  
print(e)  

r.close()
