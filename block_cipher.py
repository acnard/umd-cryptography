
from random import randint

def gen_bytevals(n):
    """
    n is an int, the number of random byte values we want to generate

    returns a list of n ints, where each int is in the range 0->255 inclusive

    """
    vals = [randint(0, 255) for i in range(n) ]
    return vals

def encrypt(s, k):
    """
    s is a string, the plaintext message to encrypt
    k is a list of ints, the keybytes to use for the encryption
    """
    ## convert to values
    m = [ord(c) for c in s]
    n = len(m)

    assert len(k)==n    # key must be as long as the message

    ## generate equal length random r
    r = gen_bytevals(n)

    ## compute r XOR k XOR m
    c2 = [r[i]^k[i]^m[i] for i in range(n) ]

    return(r+c2)

def decrypt(c, k):
    """
    c is a list of ints, the ciphertext 
    k is a list of ints, the keybytes to use for the decryption
    (c is twice as long as k)

    returns the decrypted string
    """
    assert len(c) == 2*len(k)

    ##ciphertext is twice as long as message text
    n = len(c) // 2

    ## split into two halves
    r = c[:n]
    c2 = c[n:]

    ## to decrypt, apply key to first half, then XOR the result with 
    ## the second half
    pvals = [k[i]^r[i]^c2[i] for i in range(n) ]

    ## convert plaintext vals to a string
    s = ""
    for val in pvals:
        s = s + chr(val)
    
    return s

def test(s):
    """
    s is a string on which to test encryption and decryption
    """
    ## generate equal-length key
    k = gen_bytevals(len(s))

    ciphervals = encrypt(s, k)
    print("cipher values", ciphervals)


    plaintext = decrypt(ciphervals,k)

    return plaintext
