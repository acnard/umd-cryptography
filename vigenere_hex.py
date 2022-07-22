# apply vigenere cipher with hexadecimal XOR
# note that if plaintext XOR key = ciphertext
# then ciphertext XOR key = plaintext
# ie you get the plaintext back by reapplying XoR by the same key

keys = [0x00, 0x00]  

## in python, ord(c) will give you the integer value of a single character
## and chr(n) will give you the ascii character corresponding to a value
## also hex(n) gives you a string that is the hex representation of an integer
##
## to convert a hex string to an int you can use int(hexstring, 16)
## eg int("FF", 16) = 255 
## also int("0xff", 16) = 255

def xor_char(c, byte):
    """
    c is a string, a lower case letter
    byte is an integer between 0 and 255, corresponding to a 
    hex value between 0x00 and 0xFF

    returns the result of c's ascii value XOR byte 
    """
    assert len(c)==1
    assert byte >= 0x00 and byte <= 0xFF

    cval = ord(c)
    # print("character is", c, "with hex value", hex(cval) )
    # print("byte to XOR by is ", hex(byte))

    result = cval ^ byte
    # print("result is", hex(result))
    return hex(result)[2:]

def encrypt(keys, plaintext):
    """
    plaintext is a string, the message to encrypt
    key is a list of ints between 0 and 255 (ie between 0x00 and 0xFF)

    returns the ciphertext obtained by encrypting plaintext using keys
    
    """

    print("keys:", keys)

    ciphertext = ""

    ikey = 0  # index of next key to use
    for c in plaintext:

        ciphertext = ciphertext + xor_char(c, keys[ikey])
        ikey = (ikey+1)%(len(keys))  #increment key index

    return ciphertext

def decrypt(keys, ciphertext):
    """
    ciphertext is a string representation of hex characters to decrypt
    key is a list of ints between 0 and 255 (ie between 0x00 and 0xFF)
    returns the plaintext obtained by decrypting ciphertext using keys
    """
    plaintext = ""
    ikey = 0

    for i in range(0, len(ciphertext)-1, 2):
        hexstring = ciphertext[i:i+2]
        c = chr( int(hexstring,16) ^ keys[ikey] )
        plaintext = plaintext + c

        ikey = (ikey+1)%(len(keys))  #increment key index

    return plaintext


def test():
    inputs = ["helloworld", "mybabyjust cares for me", "I don't want to know"]
    keys = [0xff, 0xab, 0x00]

    for s in inputs:
        print(s)
        cipher = encrypt(keys, s)
        print(cipher)
        print(decrypt(keys, cipher))
