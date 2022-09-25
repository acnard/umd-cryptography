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

## HELPER FUNCTIONS

def string_to_vals(s):
    """
    s is a string of text

    returns a list of ints, the ascii value of each character in s
    """
    vals = [ord(c) for c in s]
    return vals

def vals_to_string(pvals):
    """
    pvals is a list of ints in ascii range, representing 
    plaintext characters
    returns a string, the plaintext
    """
    s = ""
    for v in pvals:
        s = s+chr(v)
    return s

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

def are_asciivals(vals):
    """
    vals is a list of ints
    returns True if every value in vals is in the range  32 =< val <127
    ie if they all represent printable characters
    otherwise False
    """
    for val in vals:
        if val >= 127 or val < 32:
            return False
    return True


def every_nth_item(items, n=1, start=0):
    """
        items is a list 
        n is an integer 
        returns a list of every nth item in items
        from specified start index of list
        (eg start=0, n=2 will return elemenst at pos 0, pos2, pos 4..)
            start=3, n=2 will return elements at pos 3, 5, 7, 9...)
        if n is < 1  or > numitems returns an empty list
    """
    numitems = len(items)
    if n > numitems or n < 1:   ## eg in 10-character long list you can at most   
                                        ## retrieve every 10th character
        return []
    else:
        return [items[i] for i in range(start, numitems, n )]
        ## eg with start=0 and n=2 the first item is at index 0 and the 
        ##     next item at index 2...
        ##   with start = 2 and n=2 the first item is at index 2 and the next at
        ##    index 4...

def sum_q_squared(bytevals):
    """
    bytevals is a list of ints in the range 0->255 inclusive 
    ie each value represents a byte

    for i from 0 to 255 computes qi = frequency of i in the list 
    (ie the number of occurences divided by number of values )

    returns the sum of all (qi)**2

    NB since each qi approx = 1/256 for uniform distribution, we expect
    returned sum = 256*(1/256)**2 = 1/256 = 0.0039 if uniform
    but larger if nonuniform
    """
    sum=0
    tot = len(bytevals)
    for i in range(256):
        sum+= (bytevals.count(i)/tot)**2

    return sum

def try_key_len(bytevals, n):
    """
    bytevals is a list of ints, corresponding to byte values of an encrypted text
    n is a candidate length of encryption key 
    returns the average qstat for that key length

    if n is correct length of the key, then every nth byte starting from 
    zero will have been encrypted with byte zero of the key, and likewise every nth byte starting from 1 will have been encrypted with byte 1 of the key, etc.  

    and all the subsequences encrypted with the same key byte will have a qstat that is nonuniform
    """
    qstats = []

    #eg if n=3 the kebyte can be 0,1, or 2,
    # and we want to take every 3rd item starting from 0, then from 1, then from 2
    for keybite in range(n): 
        nthvals = every_nth_item(bytevals, n, keybite)
        qstats.append(sum_q_squared(nthvals))

    #print("for canditate key length:", n, "qstats are", qstats)
    return sum(qstats)/len(qstats)

def find_key_val(ciphvals):
    """
    ciphvals is a list of ints, corresponding to ciphertext characters known to be encrypted with the same key

    tries XORing ciphvals with every possible value of the key (0->255) 
    (ciphval XOR keyval = plainval)
    discards any key values that yield non-ascii plaintext values
    for the others stores the resulting plaintext in a dictionary

    """
    validkeys = {}
    
    for keyval in range(256):
        plainvals = [v^keyval for v in ciphvals]
        if are_asciivals(plainvals):
            validkeys[keyval] = vals_to_string(plainvals)
    print(validkeys)

## CIPH is the ciphertext provided for the assignment 
CIPH = "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"

def find_key_len(ciphertext=CIPH, max_key_len=13):
    """ ciphertext is is a string representation of hex-encrypted characters 
        max_key_len is an int, the largest possible length of the key
        we assume the minimum key length is 1

        For n = 1 to max_key_len, we compile a list of every nth character, and get 
        the q statistic for that. 
        When n is the right key length, the q statistic 
        will be much higher than 1/256 = .0039 (the uniform distribution case) 
    """
    ## convert ciphertext hexstring to a list of integer values
    ciphvals = hexstring_to_vals(ciphertext)

    ## for each possible key length n, create sublist of every nth character
    ## and compute stats for the sublist
    qstats = []
    for n in range(1, max_key_len+1):
       qstats.append(try_key_len(ciphvals,n)) #list of every nth item

    print(qstats)

    ## the key length will correspond to the highest qstat
    maxq = max(qstats)
    keylen = qstats.index(maxq)+1  #variance for keylen1 is 0th element in list, etc.
    print("the keylength is", keylen)  #key length = 7 for CIPH


def decrypt(ciphvals, keyvals):
    """
    ciphvals is a list of ints, corresponding to the ciphertext
    keyvals is a list of ints, corresponding to the keybytes

    returns a string, the decrypted plaintext 
    """

    plainvals = []
    ikey=0

    for cval in ciphvals:
        plainvals.append(cval^keyvals[ikey])
        ikey = (ikey+1)%(len(keyvals))  #increment key index
    
    return vals_to_string(plainvals)

        
