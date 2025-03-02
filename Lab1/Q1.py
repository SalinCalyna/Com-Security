from pwn import * 
 
host = '172.26.201.109' 
port = 1111 
r = remote(host, port) 

chal_byte = r.recvuntil(b'$ ') 
chal_str = chal_byte.decode('utf-8')[:-3] 
print(chal_str) 
 
print('1') 
r.sendline(b'1') 

chal_byte = r.recvuntil(b'C: ') 
chal_str = chal_byte.decode('utf-8')[:-4] 
print(chal_str) 

C = r.recvuntil(b' ').decode('utf-8')[:-4] 
print("C:",C) 

K1 = r.recvline().decode('utf-8')[:-1] 
print("K:",K1) 
 
K1 = int(K1) 
C = str(C) 
 
#decrypt ถอดรหัส
def decrypt(C,K1): 
    answer = "" 
    for char in C: 
        answer += chr(((ord(char) - 97 - K1) % 26 )+ 97) 
    return answer 
     
decrypt_ans = decrypt(C,K1) 
r.sendline(str(decrypt_ans).encode('utf-8')) 
e = r.recvuntil(b":").decode('utf-8') 
print(e,decrypt_ans) 
 
#Q1.2 
chal_byte = r.recvuntil(b'P: ') 
chal_str = chal_byte.decode('utf-8')[:-4] 
print(chal_str) 
P = r.recvuntil(b'K: ').decode('utf-8')[:-4] 
print("P:",P) 
K = r.recvline().decode('utf-8')[:-1] 
print("K:",K) 
 
P = str(P) 
K = int(K) 
 
#encrypt เข้ารหัส
def encrypt(P,K): 
    answer = "" 
    for char in P: 
        answer += chr(((ord(char) - 97 + K) % 26 )+ 97) 
    return answer 
 
encrypt_ans = encrypt(P,K) 
 
r.sendline(str(encrypt_ans).encode('utf-8')) 
e = r.recvuntil(b":").decode('utf-8') 
print(e,encrypt_ans) 
 
response = r.recvline().decode('utf-8') 
print(response) 
r.close()