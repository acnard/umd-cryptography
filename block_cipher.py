
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
    k is a list of ints, equal in length to s, the keybytes to use for the encryption
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

def chunk(s, n):
    """
    s is a sequence (eg string or list)
    n is an int
    splits s into n-length chunks and returns a list 
    of the resulting substrings or sublists 

    if n>len(s) just returns s
    if len(s) is not divisible by n, the last substring will have less
    than n characters

    """
    chunks = [ s[i:i+n] for i in range(0, len(s), n) ]
    return(chunks)

def pkcs5_pad(s, b):
    """
    s is a string
    b is an int, the block length 

    pads s so that its length is a multiple of b: 
    - uses p padding bytes of value p
    - if s is already a multiple of b, still pads with b bytes of value b

    returns the padded string
    
    """

    p = b - len(s)%b  #number of padding characters required

    pad_char = chr(p)  #value of the padding character is also p

    s = s+ pad_char*p
    return s


def encrypt_2n(s, k):
    """ 
    s is a string, the  message to encrypt.
    k is a list of ints, the keybytes to use for encryption

    breaks up the message s into chunks equal to the keylength
    and encrypts each with the 2n block cipher

    returns a list of ints, the concatenated result 

    """
    b = len(k)  # get the block length 

    s = pkcs5_pad(s, b)  # pads the string so len(s) is a multiple of b

    chunks = chunk(s, b)   # split s into b-length chunks

    #key = gen_bytevals(n)  # generate n-length key

    ciphervals = []
    for c in chunks:
        ciphervals += encrypt(c, k)

    return ciphervals

def decrypt_2n(c, k):
    """
    c is a list of ints, the ciphertext
    k is a list of ints, the keybytes to use for decryption

    """
    b = len(k)  # get the block length

    chunks = chunk(c, 2*b) #encryption doubles the block size

    s = ""
    for c in chunks:
        s = s+decrypt(c,k)

    return s


def test2n(s, b):
    """
    s is a string on which to test encryption and decryption
    b is an int, the block size we want to use
    """
    ## generate key of length b
    k = gen_bytevals(b)

    ciphervals = encrypt_2n(s, k)
    print("cipher values", ciphervals)


    plaintext = decrypt_2n(ciphervals,k)

    return plaintext