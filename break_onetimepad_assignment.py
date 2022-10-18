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

### helper functions
def hexstring_to_vals(hexstring):
    """ 
    hexstring is a string representation of hex bytes
            eg "F96DE8C2" 
    it must contain even number of valid chars (0->9 , A->F , a->f)
    returns a list of ints, the values of the bytes
    """
    assert len(hexstring)%2 == 0

    vals = []   #will contain int value of each hex byte
    for i in range(0, len(hexstring)-1, 2):
        pair = hexstring[i:i+2]  #this is a string like "E3"
        val = int(pair, 16)      # throws value error if pair includes nonhex chars
        vals.append(val)

    ## nb with list comprehension:
    ## vals = [int(hexstring[i:i+2], 16)] for i in range(0, len(hexstring)-1, 2)

    return vals

## The seven ciphertexts, representing 31-character ascii strings
## these were all encrypted with the same key of length 31, so that:
## the byte at pos i of each ciph was XOREd with the same keybyte, 
## 
hexciphs= ["BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E",
        "BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E",
        "A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E",
        "A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F",
        "BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E",
        "A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E",
        "BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E"]

## convert each hexciph string to a list of ints
ciphs = [hexstring_to_vals(hexciphs[i]) for i in range(len(hexciphs))]
BYTES = 31  ## number of bytes in each ciphertext, and in the key

def vals_at_pos(i, intlists):
    """
    intlists is a list of equal-length lists of ints
    i is an int representing an index position in an intlist
    returns a list of ints, the ith value from each list
    """
    n = len(intlists[0])   ## number of values in each intlist
    assert i > 0 and i < n

    result = []
    for intlist in intlists:
        result.append(intlist[i])
    
    return result



def xor_vals(vals1, vals2):
    """ 
    vals1 and vals2 are equal-length lists of ints 
    returns a list of ints, the xor of vals1[i] and vals2[i] 
    """
    assert len(vals1) == len(vals2)

    return [vals1[i]^vals2[i] for i in range(len(vals1))]

def is_letterspace_pair(cval1, cval2):
    """
    cval1 and cval2 are ciphertext byte values, known to have been
    encrypted with the same key. 
    consequently, the XOR of the cvals = the XOR of the plaintext values.

    Ascii letters start with binary    01
    Asci space char starts with binary 00

    therefore XOR of two letters (or two spaces) starts with binary 00
              XOR of a letter and space starts with binary 01


    returns True if the two cvals are a letter and a space
    False otherwise

    """
    ## starts with binary 00 if hex byte is 0x00->0x3f
    ## starts with binary 01 if hex byte is 0x40->0x7f


    xor_val = cval1^cval2
    #print("xor result is", xor_val)
    if xor_val >= 0x40 and xor_val <= 0x7f:
        return True
    else:
        return False
def extract_keybyte(cvals):
    """
    cvals is a list of ints (in range 0->255) representing byte values
    known to have been encrypted with the same key

    if one of the cvals is an encryption of a space character, then it is
    possible to extract the key (see comments in code)

    returns the value of the keybyte if it could be extracted, otherwise
    None
    """

    ## remove duplicates
    cvals = list(set(cvals))
    
    ## need at least three distinct values
    if len(cvals)<3:
        return None

    ## compare first value v0 pairwise against all the others
    ## note that without duplicates we have all distinct letters
    ## plus possibly one space character

    v0 = cvals[0]
    othervals = cvals[1:]
    letterspace_pairs = []
    for vi in othervals:
        if is_letterspace_pair(v0, vi):
            letterspace_pairs.append(vi)
    
    ## now check how many letterspace pairs found
    ## we only compared v0 against all the other values
    ## so if v0 is the space, all will be letterspace pairs
    ## if some other value vi is the space, we will find only one pair (v0,vi)
    ## and if there are no spaces, will find no pairs

    num = len(letterspace_pairs)
    
    if num == 0:     ## cannot extract key if no spaces 
        return None   
    elif num == 1:
        space = letterspace_pairs[0] ## vi is the space, it made pair with v0
    elif num == len(othervals):
        space = v0   ## v0 is the space, it made a pair with all others
    else:
        print("unexpected letterspace_pairs count")
        return None

    ## space is the encrypted value = ord(' ') XOR key
    ## if we XOR it with ord(' ') again we recover the key
    ## (n^n = 0 and k^0 = k)
    keybyte = space ^ ord(' ')


def test():
    

### old
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


    
    