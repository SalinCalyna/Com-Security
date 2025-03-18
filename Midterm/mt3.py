from pwn import *  
from Crypto.Hash import MD5 
import re

host = '172.26.125.102'  #
port = 9876  
r = remote(host, port) 

chal_byte = r.recvuntil(b'$ ')  
chal_str = chal_byte.decode('utf-8')[:-3]  
print(chal_str)  

print('3') 
r.sendline(b'3')  

response = r.recvline().decode('utf-8')

# รับคำถามจากเซิร์ฟเวอร์
question = r.recvline().decode('utf-8')
print(question)


def oHash_SHA256(message):
    message =str.encode(message)
    h = SHA256.new(message) # type: ignore
    return h.hexdigest()[:4]

def md5_hash(plaintext):
    md5 = hashlib.md5()
    md5.update(plaintext.encode())
    return md5.hexdigest()

plaintext = " "
sha256_result = (plaintext)
md5_result = md5_hash(plaintext)



print(f"SHA-256: {sha256_result}")
print(f"MD5: {md5_result}")

response = r.recvline().decode('utf-8')  
print(response)  # แสดงข้อความที่ได้รับ

r.close()  


