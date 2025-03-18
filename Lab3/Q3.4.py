from pwn import *
from Crypto.Cipher import AES

def bytes_xor(var1, var2):
    return bytes(a ^ b for a, b in zip(var1, var2))

def hash_block(m, prev_hash):
    if len(m) > AES.block_size:
        raise ValueError("Message length exceeds AES block size")
    cipher = AES.new(m, AES.MODE_ECB)
    return bytes_xor(cipher.encrypt(prev_hash), prev_hash)

host = '0.tcp.ap.ngrok.io'
port = 16224
r = remote(host, port)

message = r.recvuntil(b'$').decode('utf-8')
print(message)

r.sendline(b'4')

q4 = r.recvuntil(b'Enter command: ').decode('utf-8')
print(q4)

laugh_token = q4.split('command with this token: ')[1].split('\n')[0].strip()
laugh_token = bytes.fromhex(laugh_token)
print(laugh_token)

new_command = b'LAUGH FLAG' + b' ' * 11
print(new_command.decode())

flag_msg = b' FLAG' + b' ' * 11
flag_token = hash_block(flag_msg, laugh_token).hex()

r.sendline(new_command)

message = r.recvuntil(b'Enter token: ').decode('utf-8')
print(message)

r.sendline(flag_token.encode())

response = r.recvall().decode('utf-8', errors="ignore")
print(response)

r.close()
