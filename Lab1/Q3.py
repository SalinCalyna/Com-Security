from pwn import *  # นำเข้า pwntools สำหรับการเชื่อมต่อเครือข่าย

# กำหนด IP และพอร์ตของเซิร์ฟเวอร์
server_ip = '172.26.201.109'
server_port = 1111

# เชื่อมต่อไปยังเซิร์ฟเวอร์
connection = remote(server_ip, server_port)

# ฟังก์ชันสำหรับหาคีย์จากข้อความเข้ารหัสและคำใบ้
def determine_key(encrypted_text, clue):
    for start_index in range(len(encrypted_text) - len(clue) + 1):  
        # เลือก substring ที่มีขนาดเท่ากับคำใบ้จาก ciphertext
        potential_match = encrypted_text[start_index : start_index + len(clue)]
        print(potential_match)

        # คำนวณคีย์ที่เป็นไปได้โดยเปรียบเทียบอักขระแรกของ substring กับคำใบ้
        possible_key = (ord(potential_match[0]) - ord(clue[0])) % 26  # ใช้ 97 แทน ord('a')
        print("Possible Key: ", possible_key)
        
        is_match = True  # ตรวจสอบว่าคีย์นี้ใช้ถอดรหัสได้ถูกต้องหรือไม่
        for encrypted_char, clue_char in zip(potential_match, clue):
            # ถอดรหัสอักขระโดยใช้คีย์ที่ได้
            decrypted_char = chr(((ord(encrypted_char) - 97 - possible_key) % 26) + 97)
            print("Decrypted char:", decrypted_char)
            if decrypted_char != clue_char:
                is_match = False
                break  # ถ้าถอดรหัสไม่ตรงกับคำใบ้ ให้ลองคีย์อื่น
        if is_match:
            return possible_key  # คืนค่าคีย์ที่ถูกต้อง
    
# ฟังก์ชันถอดรหัสข้อความโดยใช้คีย์ที่หาได้
def decode_message(encrypted_message, key):
    decoded_message = ""
    key_value = int(key)
    for char in encrypted_message:
        # ใช้คีย์ในการเลื่อนตัวอักษรกลับไปเป็นข้อความต้นฉบับ
        decrypted_char = chr(((ord(char) - 97 - key_value) % 26) + 97)
        decoded_message += decrypted_char
    return decoded_message  # คืนค่าข้อความที่ถอดรหัสแล้ว

# รับข้อความต้อนรับจากเซิร์ฟเวอร์
server_response = connection.recvline().decode('utf-8')
connection.sendline(b'3')  # ส่งตัวเลือก '3' ไปยังเซิร์ฟเวอร์เพื่อเลือกโจทย์
print(server_response + '3')

# รับคำถามจากเซิร์ฟเวอร์
question = connection.recvline().decode('utf-8')
print(question)

# รับข้อความเข้ารหัส (ciphertext) จากเซิร์ฟเวอร์
ciphertext_response = connection.recvline().decode('utf-8')
print(ciphertext_response)
encrypted_text = ciphertext_response.split(':')[1].strip()  # แยกข้อความเข้ารหัสออกมา
print(repr(encrypted_text))

# รับคำใบ้ (hint) จากเซิร์ฟเวอร์
hint_response = connection.recvline().decode('utf-8')
print(hint_response)

hint_response = connection.recvline().decode('utf-8')
print(hint_response)
clue = hint_response.split(':')[1].strip()  # แยกคำใบ้ออกมา
print(repr(clue))

# คำนวณหาคีย์จาก ciphertext และ clue
found_key = determine_key(encrypted_text, clue)
print("Found Key:", found_key)

# ถอดรหัสข้อความโดยใช้คีย์ที่หาได้
decoded_answer = decode_message(encrypted_text, found_key)
print(decoded_answer)

# ส่งข้อความที่ถอดรหัสแล้วกลับไปยังเซิร์ฟเวอร์
connection.sendline(decoded_answer.encode('utf-8'))

# รับข้อความตอบกลับสุดท้ายจากเซิร์ฟเวอร์
final_response = connection.recvline().decode('utf-8')
print(final_response)
