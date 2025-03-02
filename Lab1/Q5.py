from pwn import *

host = '172.26.201.109'
port = 1111

r = remote(host, port)

def encrypt(plainText, key):
    answer = ""
    for p, k in zip(plainText, key):
        plain_val = ord(p) - 97  # 'a' is 97
        key_val = ord(k) - 97  # 'a' is 97
        print(f"plainText = {plain_val}, Key = {key_val}")
        x = (plain_val + key_val) % 26
        print(f"Calculated x (plain_val + key_val) % 26 = {x}")
        
        encrypt_char = chr(x + 97)  
        answer += encrypt_char
    return answer

def decrypt(cipherText, key):
    answer = ""
    for c, k in zip(cipherText, key):
        cipher_val = ord(c) - 97  # 'a' is 97
        key_val = ord(k) - 97  # 'a' is 97
        print(f"cipherText = {cipher_val}, Key = {key_val}")
        x = (cipher_val - key_val + 26) % 26
        print(f"Calculated x (cipher_val - key_val + 26) % 26 = {x}")
        
        decrypt_char = chr(x + 97) 
        answer += decrypt_char
    return answer

response = r.recvline().decode('utf-8')
r.sendline(b'5')
print(response.strip())

question = r.recvline().decode('utf-8')
print(question.strip())

r.recvlines(9)

response = r.recvline().decode('utf-8')
plainText = response.split(':')[1].strip()

response = r.recvline().decode('utf-8')
key = response.split(':')[1].strip()

cipherText = encrypt(plainText, key)
print(f"CipherText: {cipherText}")

r.sendline(cipherText.encode('utf-8'))
response = r.recvline().decode('utf-8').strip()
print(response.strip())

response = r.recvline().decode('utf-8').strip()
cipherText = response.split(':')[1].strip()

response = r.recvline().decode('utf-8').strip()
key = response.split(':')[1].strip()

decryptedText = decrypt(cipherText, key)
print(f"Decrypted PlainText: {decryptedText}")

r.sendline(decryptedText.encode('utf-8'))
response = r.recvline().decode('utf-8').strip()
print(response.strip())
