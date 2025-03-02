# custommer_list = ["pin","puk"]
# print("Hello " + custommer_list[0])
# print("Hello " + custommer_list[1])

# # วนซ้ำ
# custommer_list = ["pin","puk"]
# for item in custommer_list:
#     text = "Hello " + item
#     print(text)

# #วนตามrang
# for index in range(10):
#     print(index)


# #วนตามrang *indexคือดำลับ(0 1 2 3 4 )
# for index in range(4):
#     print("*"*(index+1))

#รับinput 
# customers = []
# user_input = int(input()) #จำนวนรอบ
# for index in range(user_input):
#     customers.append(input("Name of User"+str(index)+":"))
#     print(customers)
# for data in customers:
#     print("Hello",data)
# while True: #ลูปวนซ้ำไม่หยุด
#     print()
 
#สร้างฟังชั่น
customers = []
def  inputAdduser(round):
    for index in range(round):
        customers.append(input("Name of User" +str(index)+ ":"))
        
def showHelloAllUser():
    for data in customers:
        print("Hello", data)

user_input = int(input()) #จำนวนรอบ
inputAdduser(user_input)
showHelloAllUser()


#เซนไล
print('5')
r.sendline(b'5')
x=r.recvline()
print(x)
r.recvlines(9)
plaintext = r.recvline().decode('utf-8').split(':')[1].strip()
print(plaintext)
key = r.recvline().decode('utf-8').split(':')[1].strip()
print(key)

