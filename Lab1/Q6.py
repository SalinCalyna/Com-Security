from pwn import *

host = '172.26.201.109'
port = 1111

r = remote(host, port)

def hex_to_byte(hex_str):
    return bytes.fromhex(hex_str)

def xor_byte(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2)) #ใช้ zip() คู่กันแล้ว XOR เพื่อคำนวณค่าที่ต้องการ

response = r.recvline().decode('utf-8')
r.sendline(b'6')
print(response+'6')

question = r.recvline().decode('utf-8')
print(question)
question = r.recvline().decode('utf-8')
print(question)

response = r.recvline().decode('utf-8')
print(response)
plaintext_byte = response.split(":")[1].strip().encode("utf-8")

response = r.recvline().decode('utf-8')
print(response)
cipher1_hex = response.split(":")[1].strip()
cipher1_byte = hex_to_byte(cipher1_hex)

response = r.recvline().decode('utf-8')
print(response)
cipher2_hex = response.split(":")[1].strip()
cipher2_byte = hex_to_byte(cipher2_hex)

print("plainText",plaintext_byte)
print("c1",cipher1_byte)
print("c2",cipher2_byte)

key = xor_byte(plaintext_byte,cipher1_byte) #คำนวนค่า OTP P1,C1
print("KEY",key)

answer = xor_byte(cipher2_byte,key) #ใช้Key ถอดรหัส C2,P2
print(answer)