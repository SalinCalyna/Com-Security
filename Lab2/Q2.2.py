from pwn import remote 
from Crypto.Util.strxor import strxor 
from binascii import unhexlify 
 
host = '172.26.201.109' 
port = 2222 
r = remote(host, port) 
 
r.sendline(b'2') 
r.recvuntil(b'Q2: ') 
Q2 = r.recvline().decode('utf-8').strip() 
print(f"Q2: {Q2}") 
 
r.recvuntil(b'C1: ') 
C1 = r.recvline().decode('utf-8').strip() 
print(f"C1: {C1}") 
 
r.recvuntil(b'C2: ') 
C2 = r.recvline().decode('utf-8').strip() 
print(f"C2: {C2}") 
 
r.recvuntil(b'P1: ') 
P1 = r.recvline().decode('utf-8').strip() 
print(f"P1: {P1}") 
 
P1_bytes = P1.encode() 
C1_bytes = unhexlify(C1) 
C2_bytes = unhexlify(C2) 
 
C1_C2_xor = strxor(C1_bytes, C2_bytes)
print(C1_bytes)
 
P2_bytes = strxor(P1_bytes, C1_C2_xor) 
print(P2_bytes)
 
P2 = P2_bytes.decode('utf-8') 
 
print(f"Recovered second plaintext: {P2}") 
 
r.recvuntil(b'$ ') 
r.sendline(P2.encode()) 
 
flag = r.recvline() 
print(flag.decode('utf-8')) 
 
r.close()