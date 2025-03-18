import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from pwn import *
from Crypto.Util.strxor import strxor 

def modify_cipher(plainText, cipherText_hex): 
    cipherText_byte = bytes.fromhex(cipherText_hex)
    plainText_byte = plainText.encode('utf-8')
    plainText_byte = pad(plainText_byte, AES.block_size)
    print(len(plainText_byte), plainText, plainText_byte)
    print(len(cipherText_byte))

    key = strxor(plainText_byte, cipherText_byte)
    
    #key = bytes(p ^ c for p, c in zip(plainText_byte, cipherText_byte))
    print(key)
    new_P = pad(b"Your bank account balance is 10,000,000 Baht", AES.block_size)
    modifyCipher = strxor(key, new_P)

    #new_P = b"Your bank account balance is 10,000,000 Baht"
    #modifyCipher = bytes(p ^ c for p, c in zip(key, new_P))
    print(len(modifyCipher), len(new_P))
   
    return modifyCipher.hex()

host = '172.26.201.109'
port = 2222

r = remote(host, port)

r.recvline()
r.sendline(b"4")
for i in range(2):
    response = r.recvline().decode('utf-8')
    print("res = ",response)

plainText = r.recvline().decode('utf-8').rstrip()
print("p-tex = ",plainText)

cipherText_hex = r.recvline().decode('utf-8')
print("c-tex = ",cipherText_hex)

IV = r.recvline().decode('utf-8')
print("IV = ",IV)

response = r.recvline().decode('utf-8')
print(response)


modifyCipher = modify_cipher(plainText, cipherText_hex)
print("mod = ",modifyCipher)
r.sendline(modifyCipher)
r.sendline(IV)

flag = r.recvline().decode('utf-8')
print(flag)