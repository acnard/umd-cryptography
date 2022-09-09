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

#from enum import unique



## HEX ENCRYPTION HELPER FUNCTIONS
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

## STATISTICAL HELPER FUNCTIONS
def calc_variance(freqs):
    """
    freqs is a list of frequencies
    computes the variance of freqs
    variance =  average of the squared differences from the mean.
    """

    # calculate mean
    m = sum(freqs) / len(freqs)

    # calculate variance using a list comprehension
    var = sum((xi - m) ** 2 for xi in freqs) / len(freqs)
    return var

## STATISTICAL HELPER CLASS
class DataStats(object):
    def __init__(self, lst):
        """ lst is a list of items that make up the dataset
        """
        self.items = lst
        self.numitems = len(self.items)
        self.distribution = self.get_distribution(self.items)
        self.frequencies = [element[1] for element in self.distribution]
        self.variance = calc_variance(self.frequencies)

    def __str__(self):
        s = "datastats\n"
        s = s +"items=\n"+str(self.items)+"\n"
        s = s + "numitems: "+ str(self.numitems) + "\n"
        s = s + "distribution:\n"+ str(self.distribution) + "\n"
        s = s + "variance: " + str(self.variance)+"\n"
        return s

    def get_top_item(self):
        """
        returns the most frequent item in self.items
        this will be the first item in the distribution, as it 
        is sorted from most frequent to least
        """
        return self.distribution[0][0]

    def get_distribution(self, lst):
        """ 
            lst is a list of items
            computes the PERCENT frequency of each item in lst where
            freq = (item count / total items)*100
            returns a list of tuples: (item, frequency) sorted from 
            highest to lowest frequency
        """
        freqs = []
        tot = len(lst)
        assert tot>0

        unique_items = list(set(lst)) #set removes duplicates
        # print("total of", tot, "items")
        # print("of which", len(unique_items), "unique items:\n", unique_items)
        for item in unique_items:
            f = round( ( 100*lst.count(item) )/tot, 3) # X100 FOR PERCENT
            freqs.append( (item, f) ) #append tuple to list
        ret = sorted(freqs,  key=lambda item:item[1], reverse=True)   
        # print("frequencies are", ret)
        return ret

    def every_nth_item(self, start=0, n=1):
        """ n is an integer 
            returns a list of every nth item in self.items
            from specified start index of list
            (eg start=0, n=2 will return elemenst at pos 0, pos2, pos 4..)
                start=3, n=2 will return elements at pos 3, 5, 7, 9...)
            if n is < 1  or > numitems returns an empty list
        """
        numitems = self.numitems
        if n > numitems or n < 1:   ## eg in 10-character long list you can at most   
                                            ## retrieve every 10th character
            return []
        else:
            return [self.items[i] for i in range(start, numitems, n )]
            ## eg with start=0 and n=2 the first item is at index 0 and the 
            ##     next item at index 2...
            ##   with start = 2 and n=2 the first item is at index 2 and the next at
            ##    index 4...


class HexDataSet(DataStats): 
    def __init__(self, hexstring):
        """ 
            hexstring is a string representation 
            of hex-encrypted characters
            eg "F96DE8C2"
        """
        self.hexstring = hexstring
        items = self.prep_ciphertext(self.hexstring) #turn into a list
        super().__init__(items)



    def __str__(self):
        s = "hexstring:"+self.hexstring+"\n"
        s = s + super().__str__() +"\n"

        return s

    def prep_ciphertext(self, ciphertext):
        """ciphertext is a string representation of hex-encrypted characters'
        eg "F96DE8C2"
        returns a list of pairs of characters, so that each item is the 
        string representation of a hex byte
        eg ["F9", "6D", "E8", "C2"]
        """
        bytes = []   #will contain string representations of each hex byte
        for i in range(0, len(ciphertext)-1, 2):
            hexstring = ciphertext[i:i+2]
            bytes.append(hexstring)

        return bytes




## ENGLISH LETTER FREQUENCY VALUES FOR REFERENCE
UNSORTED_ENG_DISTR = [('A', 8.55), ('B', 1.60), ('C',3.16), ('D', 3.87), ('E', 12.1),
            ('F', 2.18), ('G', 2.09), ('H', 4.96), ('I', 7.33), 
            ('J', 0.22), ('K', 0.81), ('L', 4.21), ('M', 2.53),
            ('N', 7.17), ('O',7.47), ('P',2.07), ('Q', 0.10),
            ('R', 6.33), ('S', 6.73), ('T', 8.94), ('U', 2.68),
            ('V', 1.06), ('W', 1.83), ('X',0.19), ('Y',1.72), ('Z', 0.11)
            ]

ENG_FREQ = [el[1] for el in UNSORTED_ENG_DISTR]
ENG_VAR = calc_variance(ENG_FREQ)
       

## functions to discover the key length
## for the assignment, key length can be anything from 1 to 13
## CIPH is the ciphertext provided for the assignment 
CIPH = "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"



def find_key_length(ciphertext=CIPH, max_key_len=13):
    """ ciphertext is is a string representation of hex-encrypted characters 
        max_key_len is an int, the largest possible length of the key
        we assume the minimum key length is 1

        For n = 1 to max_key_len, we compile a list of every nth character. If n is the key length, these characters will 
        all have been encrypted with the same key.
    """
    hx = HexDataSet(ciphertext)  #hex data set of entire ciphertext

    ## for each possible key length n, create sublist of every nth character
    ## and compute stats for the sublist
    stats = []
    for n in range(1, max_key_len+1):
        nth_hx = hx.every_nth_item(0,n) #list of every nth item

        nth_stats = DataStats(nth_hx)
        stats.append(nth_stats.variance)

    ## the key length will correspond to the highest variance
    maxvar = max(stats)
    keylen = stats.index(maxvar)+1  #variance for keylen1 is 0th element in list, etc.
    print("the keylength is", keylen)  #key length = 7 for CIPH

    return stats

def find_key(ciphertext=CIPH, keylen=7):
    """
    keylen is an int, the length in bytes of the hex key
    used to encode a message
    ciphertext is a string representation of the hex-encoded message
    """

    hx = HexDataSet(ciphertext)  #hex data set of entire ciphertext

    keylst = []       ## eg for keylen=7, key will be list of 7 ints 
                      ## the keyval at position 0 was used to encode
                      ## ciphertext elements 0, 7, 14, ...
                      ## the keyval at posiiton 1 was used to encode
                      ## ciphertext elements 1, 8, 15, ... etc.
    for pos in range(keylen):
        #extract every nth item starting from this pos
        nth_list = hx.every_nth_item(pos, keylen)
        #generate a stats object for this list
        nth_stats = DataStats(nth_list)
        #get the most frequent item, we will assume this encodes space character
        # which has integer value 32
        topitem = nth_stats.get_top_item()

        # topitem is returned as a string representation of a hex byte
        # eg "3F" , but we now change it into an actual int value
        # of an encrypted character
        cipherval = int(topitem, 16)

        # encryptedtext XOR plaintext = key

        k = cipherval ^ ord(' ')
        keylst.append(k)
    print(keylst)
    return keylst





