from pwn import *
from Crypto.Hash import MD5

host = '172.26.201.109'
port = 3333
r = remote(host, port)

# รับข้อมูลจากเซิร์ฟเวอร์
chal_byte = r.recvuntil(b'$ ')
chal_str = chal_byte.decode('utf-8').strip()
print(f"Received: {chal_str}")

# ส่งข้อมูล "2" ไปยังเซิร์ฟเวอร์
print('2')
r.sendline(b'2')

# รับข้อความ UUIDs และ Hashes
question = r.recvuntil(b"$").decode().strip()
print(f"Received question:\n{question}")

lines = question.split("\n")

# ฟังก์ชัน oHash เพื่อสร้างแฮชจากข้อความ
def oHash(message):
    message = str.encode(message)
    h = MD5.new(message)
    return h.hexdigest()[:5]

# ดึงค่าแฮชจากข้อความ
target_hash_match = re.search(r'([0-9a-f]{5})\n\nEnter password to login:', question)
if target_hash_match:
    target_hash = target_hash_match.group(1)
    print(f"Target hash: {target_hash}")
else:
    print("ไม่สามารถดึงค่า Hash ได้")
    r.close()
    exit()

# ลองรหัสผ่านทั้งหมดตั้งแต่ 000000 ถึง 999999
found = False
for i in range(1000000):
    password = f"{i:06}"
    if oHash(password) == target_hash:
        print(f"Password found: {password}")
        r.sendline(password.encode('utf-8'))
        found = True
        break

# ปิดการเชื่อมต่อ
r.close()
