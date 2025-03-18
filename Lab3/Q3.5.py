from pwn import *
import hmac
import hashlib
import base64
from Crypto.Cipher import AES

host = '0.tcp.ap.ngrok.io'
port = 16224
r = remote(host, port)

def receive_message():
    return r.recvuntil(b'$').decode('utf-8')

def send_message(message):
    r.sendline(message.encode())

def compute_hmac(key, message):
    hmac_result = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(hmac_result).decode()

def encrypt_with_aes_gcm(key, nonce, header, message):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return base64.b64encode(ciphertext).decode(), base64.b64encode(tag).decode()

message = receive_message()
print(message)

send_message('5')

q5 = receive_message()
print(q5)

key = b'977-213-Computer'
message = b'Username:Alice'

hmac_base64 = compute_hmac(key, message)
print(hmac_base64)

send_message(hmac_base64)

res1 = r.recvline().decode('utf-8')
print(res1)

res2 = r.recvline().decode('utf-8')
print(res2)

res3 = r.recvline().decode('utf-8')
print(res3)

header = res2.split('Header: ')[1].split('\n')[0].encode()
print(header)

nonce_b64 = res3.split('Nonce in base64: ')[1].split('\n')[0]
nonce = base64.b64decode(nonce_b64)
print(nonce)

ciphertext_b64, tag_b64 = encrypt_with_aes_gcm(key, nonce, header, message)

send_message(ciphertext_b64)
send_message(tag_b64)

res = r.recvline().decode('utf-8')
print(res)

r.close()
