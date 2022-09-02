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
    print("character is", c, "with hex value", hex(cval) )
    print("byte to XOR by is ", hex(byte))

    result = cval ^ byte
    print("result is", hex(result))
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




### ciphertext to break 
### The plaintext contains upper- and lower-case letters, punctuation, and
### spaces, but no numbers. (from unicode 0x20 to 0x7e)
### The key length is between 1 and 13
ciph = "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"

## unsorted english letter frequencies expressed as 
## percentages

UNSORTED_ENG_FREQ = [('A', 8.55), ('B', 1.60), ('C',3.16), ('D', 3.87), ('E', 12.1),
            ('F', 2.18), ('G', 2.09), ('H', 4.96), ('I', 7.33), 
            ('J', 0.22), ('K', 0.81), ('L', 4.21), ('M', 2.53),
            ('N', 7.17), ('O',7.47), ('P',2.07), ('Q', 0.10),
            ('R', 6.33), ('S', 6.73), ('T', 8.94), ('U', 2.68),
            ('V', 1.06), ('W', 1.83), ('X',0.19), ('Y',1.72), ('Z', 0.11)
            ]

## Just the percentages, sorted descending
DISTRIBUTION = sorted([item[1] for item in UNSORTED_ENG_FREQ], reverse=True)


def prep_ciphertext(txt=ciph):
    """
    txt is a string representation of hex characters 
    returns a corresponding list of values (ints)

    """    
    values = []
    for i in range(0, len(txt)-1, 2):
        hexstring = txt[i:i+2]
        values.append( int(hexstring,16) ) 

    # for value in values:
    #     print(hex(value))
    return values
    

def get_nth_values(values, n):
    """
    values is a list of ints, representing a sequence of characters in a message. n is an int.
    returns a list of every nth element in values, starting from i=0
    eg if n=1 just returns values list, if n=2 returns a list of values[0], values[2], values[4] etc.
    """

    ret = [values[i] for i in range(0, len(values), n)]

    return ret

def calc_distrbution(values):
    """
    values is a list of ints, representing a sequence of characters in a message
    returns a list of floats, the percentage occurrence of each value in the list, sorted descending
    """

    tot = len(values)  #total number of values in the list
    ret = []

    already_counted = []

    for value in values:
        if value not in already_counted:
               freq = 100*( values.count(value) )/tot  # value freq as percentage
               already_counted.append(value)
               ret.append( round(freq,2) )

    ret.sort(reverse=True)
    return ret


def find_key_length(values, max=13):
    """
    values is a list of ints, representing a sequence of characters in a message
    max is an int, the maximum possible key length
    for n from 1 up to max (inclusive)
    prints out the frequency distribution for every nth character
    """

    for n in range(1, max+1):
        print("for key length", n)
        print("distribution is:\n", calc_distrbution(get_nth_values(values,n)))

def trykey(values, keylen=7):
    """
    values is a list of ints, representing a sequence of characters in a message  
    keylen is an int, the presumed length of the key
    """

    stream = 


def test():
    # inputs = ["helloworld", "mybabyjust cares for me", "I don't want to know"]
    # keys = [0xff, 0xab, 0x00]

    # for s in inputs:
    #     print(s)
    #     cipher = encrypt(keys, s)
    #     print(cipher)
    #     print(decrypt(keys, cipher))

    print("English letter distribution:\n", DISTRIBUTION)
    vals = prep_ciphertext()
    find_key_length(vals)

