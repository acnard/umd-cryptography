# apply vigenere cipher with hexadecimal XOR
# note that if plaintext XOR key = ciphertext
# then ciphertext XOR key = plaintext
# ie you get the plaintext back by reapplying XoR by the same key

## in python, ord(c) will give you the integer value of a single character
## and chr(n) will give you the ascii character corresponding to a value
## also hex(n) gives you a string that is the hex representation of an integer
##
## to convert a hex string to an int you can use int(hexstring, 16)
## eg int("FF", 16) = 255 
## also int("0xff", 16) = 255

from enum import unique


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

def every_nth_item(lst, n):
    """ lst is a list of items, n is an integer 
        returns a list of every nth item
        if n is <= 1 (return every item) or > list length
        returns an empty list
    """
                          
    if n > len(lst) or n < 1:   ## eg in 10-character long list you can at most   
                                ## retrieve every 10th character
        return []
    else:
        return [lst[i] for i in range(n-1, len(lst), n )]

def get_frequencies(lst):
    """ lst is a list of items
        computes the frequency of each item = item count / total items
        returns a list of tuples: (item, frequency) sorted from 
        highest to lowest frequency
    """
    freqs = []
    tot = len(lst)
    assert tot>0
    unique_items = list(set(lst)) #set removes duplicates
    for item in unique_items:
        f = round( lst.count(item)/tot, 4)
        freqs.append( (item, f) ) #append tuple to list

    return sorted(freqs,  key=lambda item:item[1], reverse=True)   




## functions to discover the key length
## for the assignment, key length can be anything from 1 to 13
## CIPH is the ciphertext provided for the assignment 
CIPH = "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"


def find_key_length(ciphertext=CIPH, max_key_len=13):
    """ ciphertext is is a string a string representation of hex-encrypted characters 
        max_key_len is an int, the largest possible length of the key
        we assume the minimum key length is 1

        For n = 1 to max_key_len, we compile a list of every nth character. If n is the key length, these characters will 
        all have been encrypted with the same key.
    """

    ## prepare the list of hex bytes
    bytes = []   #will contain string representations of each hex byte
    for i in range(0, len(ciphertext)-1, 2):
        hexstring = ciphertext[i:i+2]
        bytes.append(hexstring)

    #print(bytes)
    frequencies = {}  #dict mapping an int, keylength n ---> list of tuples (item, frequency)
    ## for each possible key length n, extract a list of every nth character
    for n in range(1, max_key_len+1):
        nth_chars = every_nth_item(bytes,n)
        freqs = get_frequencies(nth_chars) #get the frequencies
        frequencies[n]= freqs

    # print("keys in dictionary", frequencies.keys())
    # for key in frequencies.keys():
    #     print(frequencies[key])
    
    return frequencies



