from pwn import *
from Crypto.Cipher import AES
from Crypto.Util import Counter
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
print("Received after option 2:", challenge_text)  

import re

c1_match = re.search(r'C1: ([0-9a-fA-F]+)', challenge_text)
c2_match = re.search(r'C2: ([0-9a-fA-F]+)', challenge_text)
p1_match = re.search(r'P1: ([\x00-\x7F]+)', challenge_text)

if c1_match and c2_match and p1_match:
    c1_hex = c1_match.group(1)
    c2_hex = c2_match.group(1)
    p1_text = p1_match.group(1)
else:
    print("Error: Unable to extract C1, C2, and P1 from the challenge.")
    connection.close()
    exit()

c1_bytes = bytes.fromhex(c1_hex)
c2_bytes = bytes.fromhex(c2_hex)

p1_bytes = p1_text.encode('utf-8')

keystream = bytes([a ^ b for a, b in zip(c1_bytes, p1_bytes)])

p2_bytes = bytes([a ^ b for a, b in zip(keystream, c2_bytes)])

p2_text = p2_bytes.decode('utf-8', errors='ignore')

print("Recovered P2:", p2_text)

print("Sending P2 to the server...")
connection.sendline(p2_text.encode('utf-8'))

time.sleep(2) 

try:
    server_response = connection.recv(timeout=3)  # Receive response from server with a 3-second timeout
    print("Server response:", server_response.decode('utf-8'))
except EOFError:
    print("Connection closed by the server.")

connection.close()
