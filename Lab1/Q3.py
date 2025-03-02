from pwn import *

server_ip = '172.26.201.109'
server_port = 1111

connection = remote(server_ip, server_port)

def determine_key(encrypted_text, clue):
    for start_index in range(len(encrypted_text) - len(clue) + 1):  
        potential_match = encrypted_text[start_index : start_index + len(clue)]
        print(potential_match)

        possible_key = (ord(potential_match[0]) - ord(clue[0])) % 26  # ใช้ 97 แทน ord('a')
        print("Possible Key: ", possible_key)
        
        is_match = True
        for encrypted_char, clue_char in zip(potential_match, clue):
            decrypted_char = chr(((ord(encrypted_char) - 97 - possible_key) % 26) + 97)  # ใช้ 97 แทน ord('a')
            print("Decrypted char:", decrypted_char)
            if decrypted_char != clue_char:
                is_match = False
                break
        if is_match:
            return possible_key
    
def decode_message(encrypted_message, key):
    decoded_message = ""
    key_value = int(key)
    for char in encrypted_message:
        decrypted_char = chr(((ord(char) - 97 - key_value) % 26) + 97)  # ใช้ 97 แทน ord('a')
        decoded_message += decrypted_char
    return decoded_message

server_response = connection.recvline().decode('utf-8')
connection.sendline(b'3')
print(server_response + '3')

# รับคำถามจากเซิร์ฟเวอร์
question = connection.recvline().decode('utf-8')
print(question)

# รับ ciphertext จากเซิร์ฟเวอร์
ciphertext_response = connection.recvline().decode('utf-8')
print(ciphertext_response)
encrypted_text = ciphertext_response.split(':')[1].strip()
print(repr(encrypted_text))

# รับ hint จากเซิร์ฟเวอร์
hint_response = connection.recvline().decode('utf-8')
print(hint_response)

hint_response = connection.recvline().decode('utf-8')
print(hint_response)
clue = hint_response.split(':')[1].strip()
print(repr(clue))

found_key = determine_key(encrypted_text, clue)
print("Found Key:", found_key)

decoded_answer = decode_message(encrypted_text, found_key)
print(decoded_answer)

connection.sendline(decoded_answer.encode('utf-8'))

final_response = connection.recvline().decode('utf-8')
print(final_response)
