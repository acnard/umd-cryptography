## one time pad
## the plaintext is provided in ascii
##
# 
# ## in python, ord(c) will give you the integer value of a single character
## and chr(n) will give you the ascii character corresponding to a value
## also hex(n) gives you a string that is the hex representation of an integer
##              but with leading 0x and no leading zeros
##
## to convert a hex string to an int you can use int(hexstring, 16)
## eg int("FF", 16) = 255 
## also int("0xff", 16) = 255
# 
#  
from pydoc import plain
from random import randint

def string_to_vals(s):
    """
    s is a string of text

    returns a list of ints, the ascii value of each character in s
    """
    vals = [ord(c) for c in s]
    return vals

def vals_to_hexstring(vals):
    """
    vals is a list ints, corresponding to byte values, in range 0->255
    returns a string, the hexadecimal representation of those bytes
    """
    s = ""
    for val in vals:
        assert val >=0 and val <=255   # must represent a byte
        hexval = hex(val)[2:]  #strip out leading '0x'
        if len(hexval)==1:
            hexval = '0'+ hexval  #and add leading zero if needed
        s = s + hexval

    return s

def genkey(n):
    """
    n is an int, the length (number of bytes) of the key we want to generate
    returns the key as a list of ints, where each int is in the range 0-->255

    """
    key = [randint(0, 255) for i in range(n)]
    return key

def encrypt(plaintext):
    """
    plaintext is a string
    generates a random key and encodes the plaintext with it
    """
    plainvals = string_to_vals(plaintext)
    n = len(plainvals)  #num of bytes in plaintext

    ## generate key with same number of bytes
    keyvals = genkey(n)
    print("key is", keyvals)

    ciphvals = [plainvals[i]^keyvals[i] for i in range(n)]

    print("ciphertext is", vals_to_hexstring(ciphvals))
    
    