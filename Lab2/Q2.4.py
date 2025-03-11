import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from pwn import *

def modify_cipher(plainText, cipherText_hex): 
    cipherText_byte = bytes.fromhex(cipherText_hex)
    plainText_byte = plainText.encode('utf-8')
    key = bytes(p ^ c for p, c in zip(plainText_byte, cipherText_byte))
    #print(key)
    modifyCipher = bytes(k ^ p for k, p in zip(key, b"Your bank account balance is 10,000,000 Baht"))
    return modifyCipher.hex()

host = '172.26.201.109'
port = 2222

r = remote(host, port)

r.recvline()
r.sendline(b"4")
for i in range(2):
    response = r.recvline().decode('utf-8')
    print(response)

plainText = r.recvline().decode('utf-8')
print(plainText)

cipherText_hex = r.recvline().decode('utf-8')
print(cipherText_hex)

IV = r.recvline().decode('utf-8')
print(IV)

response = r.recvline().decode('utf-8')
print(response)


modifyCipher = modify_cipher(plainText, cipherText_hex)
print(modifyCipher)
r.sendline(modifyCipher)
r.sendline(IV)

flag = r.recvline().decode('utf-8')
print(flag)