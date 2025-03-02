from pwn import *
from Crypto.Cipher import AES
from tqdm import tqdm
from pwn import *
from Crypto.Cipher import AES
from tqdm import tqdm
 
# Split the ciphertext into 16-byte blocks and check if any block repeats
def check_ciphertext(ciphertext1):
    block_size = 16  
    blocks = [ciphertext1[i:i+block_size] for i in range(0, len(ciphertext1), block_size)]
    
    
    print("Ciphertext blocks:")
    for idx, block in enumerate(blocks):
        print(f"Block {idx}: {block.hex()}")
    
    # Compare each block with every other block
    for i in range(len(blocks)):
        for j in range(i + 1, len(blocks)):
            if blocks[i] == blocks[j]:
                return True  # Found matching blocks
    
    return False  # No matching blocks
 
host = "172.26.201.109"
port = 2222
r = remote(host, port)
message = r.recvuntil(b'$')
print(message.decode('utf-8'))
r.sendline(str(3))
q3 = r.recvuntil(b'$')
print(q3.decode('utf-8'))
temp_text = b'\00'*14 # 14 bytes
r.sendline(temp_text.hex())
ciphertext_main = r.recvuntil(b'$').split(b'\n')[0].strip()
print("ciphertext:", ciphertext_main.decode('utf-8'))
# check_ciphertext(ciphertext_main)
 
# check_ciphertext(ciphertext_main)
byte_value1_str ='00'
byte_value2_str ='00'
 
found_combination = False
for value1 in tqdm(range(256), desc="Testing byte1 values", unit="byte1"):  # 00 01 02 --> ff
    byte_value1 = format(value1, '02X')  # 0 -> 00, 5 -> 05, a-f
    for value2 in tqdm(range(256), desc="Testing byte2 values", unit="byte2"):
        byte_value2 = format(value2, '02X')
        byte_value1_str = byte_value1   # 00
        byte_value2_str = byte_value2   # 01
        new_text = temp_text + bytes.fromhex(byte_value1_str) + bytes.fromhex(byte_value2_str) + temp_text
        print(new_text.hex())
        # 2+14+\00\ff+\00\ff+14
        r.sendline(new_text.hex())
        cipher_text = r.recvuntil(b'$').split(b'\n')[0].strip()
 
        if check_ciphertext(cipher_text):
            found_combination = True
            break
 
    if found_combination:
        break
 
if found_combination:
    print("We found it!")
    print("Byte 1:", byte_value1_str)
    print("Byte 2:", byte_value2_str)
 
    r.sendline("c")
    data1 = r.recvline().decode("utf-8")
    text1 = byte_value1_str + byte_value2_str
    text1 = bytes.fromhex(text1)
    print(text1.hex())
    r.sendline(text1.hex())
    data1 = r.recvline().decode("utf-8")
    print(data1)
 
else:
    print("No matching combination found.")
 
r.close()