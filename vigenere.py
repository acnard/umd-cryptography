# apply vigenere cipher

## can use <string>.index() function to obtain index of any character in the string
alphabet = "abcdefghijklmnopqrstuvwxyz"


def shift_char(c, offset):
    """
    c is a string, a lower case letter
    offset is an integer
    returns c shifted by offset 
    """


    assert c in alphabet
    assert len(c)==1

    i = alphabet.index(c)     #original 0-25 value of the character

    ishifted = (i + offset) % 26 #circular shift by offset

    return alphabet[ishifted]

def encrypt(key, plaintext, mult=1):
    """
    key and plaintext are strings
    we assume they all use only lower case letters of the alphabet
    returns the ciphertext obtained by encrypting plaintext using key

    mult = 1 for encrypting, you can set it to -1 for decrypting
    
    """

    intkeys = []  # key as a list of integers
    for c in key:

        intkeys.append(alphabet.index(c))


    print("intkeys:", intkeys)

    ciphertext = ""

    ikey = 0  # index of next key to use
    for c in plaintext:
        ciphertext = ciphertext + shift_char(c, intkeys[ikey]*mult)
        ikey = (ikey+1)%(len(intkeys))  #increment key index

    return ciphertext






