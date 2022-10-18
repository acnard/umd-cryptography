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

from itertools import combinations
import re
from webbrowser import get

########################
###  helper functions ##
########################
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


def string_to_vals(s):
    """
    s is a string of text

    returns a list of ints, the ascii value of each character in s
    """
    vals = [ord(c) for c in s]
    return vals

def are_printable_asciivals(vals):
    """
    vals is a list of ints
    returns True if every value in vals is in the range  32 =< val <127
    ie if they all represent printable characters
    (nb 127 is DEL so we exclude it)
    otherwise False
    """
    for val in vals:
        if val >= 127 or val < 32:
            return False
    return True

def vals_to_string(vals):
    """
    vals is a list of ints, representing printable ascii characters
    returns the corresponding string  
    """
    s = ""
    assert are_printable_asciivals(vals)
    for val in vals:
        s = s + chr(val)

    return s

def extract_pairs(items):
    """ items is a list
        returns a list of tuples, all the possible pairs of items
        from the string, without repetition (order does not matter) 
        eg "ddefge"  -> the pairs are de, df, dg, ef, eg, fg
    """

   ## remove duplicates to get unique items
    u_items = list(set(items))
    pairs = list(combinations(u_items, 2))

    return pairs

def get_addends(tot):
    """
    tot is an int
    returns a list of tuples, all pairs of nonzero values s1, s2 such that s1+s2=tot
    order doesn't matter
    eg for tot = 10 returns [(1,9), (2,8), (3,7), (4,6), (5,5)]

    """
    sums = []
    for s1 in range(1,1+tot//2):
        sums.append( (s1, tot-s1) )
    return sums

def test_helpers(s):
    """s is a string, to use for running the test 
    """
    #get hexstring representation of the string
    hx = vals_to_hexstring( string_to_vals(s) )
    print("hex=", hx)

    # now try to get original string back
     
    st = vals_to_string( hexstring_to_vals(hx) )

    print("return string=", st)

    if s != st:
        print("no match")

    # do the combinations
    chars = list(s)
    print(extract_pairs(chars))

########################
###  end helpers #######
########################

def is_letter_and_nonletter(cval1, cval2):
    """
    cval1 and cval2 are two plaintext values or, alternatively, 
    two ciphertext byte values encrypted with the same key. 
    
    NB this is equivalent because, if the same key was used,
    the XOR of the cvals = the XOR of pvals. Proof:

    Given cval1=(key XOR pval1) and (cval2= key XOR pval2)

    cval1 XOR cval2 = (key XOR pval1) XOR (key XOR pval2)
                     = (key XOR key) XOR (pval1 XOR pval2) 
                     = 0 XOR (pval1 XOR pval2)
                     = pval1 XOR pval2


    Ascii letters start with binary    01
    Asci numbers and (most) punctuation start with binary 00

    therefore XOR of two letters (or two nonletters) starts with binary 00
              XOR of a letter and nonletter starts with binary 01

    returns True if the two cvals are a letter and a nonletter
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


def find_nonletters(vals):
    """
    vals is a list of ints (in range 0->255) representing byte values
    known to have been encrypted with the same key
    (or, equivalently, a list of ints representing plaintext byte values)

    returns a list of ints, all the vals that correspond to nonletters
    """
    ## remove duplicates 
    u_vals = list(set(vals))
    tot = len(u_vals)          # total number of unique values we are working with

    #extract unordered pairs
    pairs = list(combinations(u_vals, 2))

    ## select those that are letter-nonletter pairs
    letter_nonletter_pairs = [(v1,v2) for (v1,v2) in pairs if is_letter_and_nonletter(v1, v2)]

    ## now for each letter-nonletter pair v1,v2, we know that v1 XOR v2 starts with binary 01
    ## so it is as if the XOR of v1 and v2 corresponds to a letter
    ## therefore we can use is_letter_and_nonletter again to determine which member
    ## of each pair is the nonletter.
    nonletters = []

    for (v1, v2) in letter_nonletter_pairs:
        if v1 not in nonletters and v2 not in nonletters:
            if is_letter_and_nonletter(v1^v2, v1):
                nonletters.append(v1)
            else:
                nonletters.append(v2)

    return nonletters

    ## check how many letter-nonletter pairs were found:
    ##    0: it's either all letters (or, less likely, all nonletters), cannot do anything
    ##    1: can only happen if cvals has len=2, ie contains one letter and one nonletter
    ##    2: one nonletter + two letters, or two letters and one nonletter (tot=3)
    ##    3: one nonletter and three letters, or vice versa (tot=4)
    ##    4: one nonletter and 4 letters, or vice versa, or two and two (tot=5 or 4)
    ##    5: 5+1 or 1+5 (tot=6)
    ##    6: 6+1, 1+6, 3+2, 2+3 (tot=7 or 5)
    ##    7: 7+1 or 1+7 (tot=8)
    ##    8: 8+1 or 1+8 or 2+4 or 4+2 (tot=9 or 6)
    ##    9: 9+1 or 1+9 or 3+3 (tot=10 or 6)
    ##    10: 10+1 or 1+10 or 2+5 or 5+2 (tot=11 or 7)
    ##    11: 11+1 or 1+11  (tot=12)
    ##    12: 12+1 or 1+12 or 2+6 or 6+2 or 3+4 or 4+3 (tot= 13 or 8 or 7)
    ##
    ##   generally speaking, if n=number of nonletters and l=number of letters
    ##   and tot = n+l
    ##   then letter-nonletter pairs = l*n         (the product of the two)
    ##     ie              lnl_pairs = (tot-n)*n 
    ##
    ##   for any tot, for all sum pairs s1+s2=tot, a possible number of 
    ##   lnl_pairs is s1xs2. 
    ##       eg, if tot=7    (ie seven unique values)
    ##       possible sum pairs are (6,1), (5,2), (4,3)
    ##      &possible lnl_pairs =  6, 10, 12


    # lnl_pairs = len(letter_nonletter_pairs) 

    # if lnl_pairs < 2:
    #     return None


def extract_keybyte(cvals):
    """
    cvals is a list of ints (in range 0->255) representing byte values
    known to have been encrypted with the same key

    if one or more of the cvals is an encryption of a nonletter, then it may be
    possible to extract the key (see comments in code)

    returns the possible values of the keybyte if it could be extracted, otherwise
    None
    """
    nonletters = find_nonletters(cvals)

    if len(nonletters) == 0:
        return None   # cannot attempt to extract keybyte

    keybytes = []   #list of candidate keybytes
    counts = []  #list of tuples, nonletters with counts
    for nl in nonletters:
        counts.append( (nl, cvals.count(nl)) )

    counts.sort(key=lambda x: x[1], reverse=True)

    print(counts)

    ## if there is at least one nonletter, assume most frequent
    ## one is a space
    if len(counts) > 0:
        (spaceval, n) = counts[0]

    ## space is the encrypted value = ord(' ') XOR key
    ## if we XOR it with ord(' ') again we recover the key
    ## (n^n = 0 and k^0 = k)
    keybyte = spaceval ^ ord(' ')

    print(keybyte)


def test_extract_keybyte(s):
    """ s is a string
    """
    pvals = string_to_vals(s)

    keybyte = 245
    cvals = [pval^keybyte for pval in pvals]

    extract_keybyte(cvals)


def test_find_nonletter(s):
    """ s is a string
    """
    vals = string_to_vals(s)

    nonlettervals = find_nonletters(vals)

    nonletterchars = [chr(v) for v in nonlettervals ]
    print(nonletterchars)


def test_letterpair(c1, c2):
    """
    c1 and c2 are two single ascii characters
    returns True if they are a letter and a nonletter
    False otherwise (ie if both are letters, or both are nonletters)
    """
    return is_letter_and_nonletter(ord(c1), ord(c2))

def test():
    strs = ["helloWorld!", "01234567890", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", ".,!)(/&"]
    for s in strs:
        print(s)
        test_helpers(s)


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

  

### old
from random import randint




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


    
    