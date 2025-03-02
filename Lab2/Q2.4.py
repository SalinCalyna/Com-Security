from pwn import *

host = "172.26.201.109"
port = "2222"

r = remote(host, port)

message = r.recvuntil(b'$')
print(message.decode('utf-8'))

r.sendline(str(4))
q4 = r.recvuntil(b'CT:')
print(q4.decode('utf-8'))

lines = q4.split(b'\n')

plaintext_line = b'Your bank account balance is -10,000.00 Baht'
ciphertext_line = lines[lines.index(plaintext_line) + 1].strip()
iv_line = lines[lines.index(plaintext_line) + 2].strip()

print("Plaintext:", plaintext_line.decode('utf-8'))
print("Ciphertext:", ciphertext_line.decode('utf-8'))
print("IV:", iv_line.decode('utf-8'))

ciphertext_bytes = bytes.fromhex(ciphertext_line.decode('utf-8'))
iv_bytes = bytes.fromhex(iv_line.decode('utf-8'))

keystream = bytes([p ^ c for p, c in zip(plaintext_line, ciphertext_bytes)])

new_plaintext = b"Your bank account balance is 10,000,000 Baht"  

new_ciphertext = bytes([p ^ k for p, k in zip(new_plaintext, keystream)])

print("New Ciphertext:", new_ciphertext.hex())

r.sendline(new_ciphertext.hex().encode('utf-8'))
res = r.recvuntil(b'IV: ')
print(res.decode('utf-8'))

r.sendline(iv_bytes.hex().encode('utf-8'))
res = r.recvline()
print(res.decode('utf-8'))

# ปิดการเชื่อมต่อ
r.close()
