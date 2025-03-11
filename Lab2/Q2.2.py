from pwn import *
import time

server_ip = '172.26.201.109'
server_port = 2222

connection = remote(server_ip, server_port)

challenge_data = connection.recvuntil(b'$ ')
challenge_text = challenge_data.decode('utf-8')
print("Received challenge:", challenge_text)

print('2')
connection.sendline(b'2')

challenge_data = connection.recvuntil(b'$ ')
challenge_text = challenge_data.decode('utf-8')
print("Q:", challenge_text)

# ใช้ string methods เพื่อดึงข้อมูล C1, C2, และ P1
c1_start = challenge_text.find("C1: ") + len("C1: ")
c1_end = challenge_text.find("\n", c1_start)
c1_hex = challenge_text[c1_start:c1_end]

c2_start = challenge_text.find("C2: ") + len("C2: ")
c2_end = challenge_text.find("\n", c2_start)
c2_hex = challenge_text[c2_start:c2_end]

p1_start = challenge_text.find("P1: ") + len("P1: ")
p1_end = challenge_text.find("\n", p1_start)
p1_text = challenge_text[p1_start:p1_end]

print(f"C1: {c1_hex}")
print(f"C2: {c2_hex}")
print(f"P1: {p1_text}")

c1 = bytes.fromhex(c1_hex)
c2 = bytes.fromhex(c2_hex)
p1 = p1_text.encode('utf-8')

# คำนวณ keystream โดยการ XOR ค่า C1 และ P1
k = bytes([a ^ b for a, b in zip(c1, p1)])
# กู้คืน P2 โดยการ XOR ค่า keystream กับ C2
p2 = bytes([a ^ b for a, b in zip(k, c2)])

# แปลง P2 เป็นข้อความที่อ่านได้
p2_text = p2.decode('utf-8', errors='ignore')
print("Recovered P2:", p2_text)

connection.sendline(p2_text.encode('utf-8'))

server_response = connection.recv(timeout=3)
print("Server response:", server_response.decode('utf-8'))

connection.close()
