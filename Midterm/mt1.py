from pwn import *  
from Crypto.Util.Padding import pad

host = '172.26.125.102'  #
port = 9876  
r = remote(host, port) 

chal_byte = r.recvuntil(b'$ ')  
chal_str = chal_byte.decode('utf-8')[:-3]  
print(chal_str)  

print('1') 
r.sendline(b'1')  
 
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def xor_bytes(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

response = r.recvline().decode('utf-8')

question = r.recvline().decode('utf-8')
print(question)

response = r.recvline().decode('utf-8')
print(response)
cipherText1_hex = response.split(":")[1].strip()  
cipherText1_byte = hex_to_bytes(cipherText1_hex)  # แปลงจาก hex เป็น byte
print(cipherText1_byte)



# รับ OTP key ในรูปแบบ hex จากเซิร์ฟเวอร์
response = r.recvline().decode('utf-8')
print(response)
otp_hex = response.split(":")[1].strip()  # ดึง OTP key ที่อยู่หลังเครื่องหมาย ':'
otp_byte = hex_to_bytes(otp_hex)  # แปลงจาก hex เป็น byte
print(otp_byte)







C2 = r.recvuntil(b' ').decode('utf-8')[:-4]  # รับข้อมูล C และลบอักขระสุดท้าย
print("C2:", C2) 

IV = r.recvuntil(b' ').decode('utf-8')[:-4]  # รับข้อมูล C และลบอักขระสุดท้าย
print("IV:", IV) 


r.sendline('host= 35.240.155.118')

response = r.recvline().decode('utf-8')  
print(response)  # แสดงข้อความที่ได้รับ

r.close()  


