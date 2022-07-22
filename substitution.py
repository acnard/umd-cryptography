# -*- coding: utf-8 -*-
"""
Created on Tue Mar 15 12:42:51 2022

@author: Anna

solution
key to decrypt the message
VIBKFERAUCDNPQOMTYWXZHSJGL

Key used to encrypt the message
HCJKFEYVBXDZPLOMNGWQIASTRU

Decrypted text
CRYPTOGRAPHICSYSTEMSAREEKTREMELYDIFFICULTTOBUILDNEVERTHELESSFORSOMEREASONMANYNONEKPERTSINSISTONDESIGNINGNEWENCRYPTIONSCHEMESTHATSEEMTOTHEMTOBEMORESECURETHANANYOTHERSCHEMEONEARTHTHEUNFORTUNATETRUTHHOWEVERISTHATSUCHSCHEMESAREUSUALLYTRIVIALTOBREAJ
"""

CIPHER = "JGRMQOYGHMVBJWRWQFPWHGFFDQGFPFZRKBEEBJIZQQOCIBZKLFAFGQVFZFWWE\
OGWOPFGFHWOLPHLRLOLFDMFGQWBLWBWQOLKFWBYLBLYLFSFLJGRMQBOLWJVFP\
FWQVHQWFFPQOQVFPQOCFPOGFWFJIGFQVHLHLROQVFGWJVFPFOLFHGQVQVFILE\
OGQILHQFQGIQVVOSFAFGBWQVHQWIJVWJVFPFWHGFIWIHZZRQGBABHZQOCGFHX"

CIPHER2 = "LIVITCSWPIYVEWHEVSRIQMXLEYVEOIEWHRXEXIPFEMVEWHKVSTYLXZIXLIKIIXPIJVSZEYPERRGERIM\
WQLMGLMXQERIWGPSRIHMXQEREKIETXMJTPRGEVEKEITREWHEXXLEXXMZITWAWSQWXSWEXTVEPMRXRSJ\
GSTVRIEYVIEXCVMUIMWERGMIWXMJMGCSMWXSJOMIQXLIVIQIVIXQSVSTWHKPEGARCSXRWIEVSWIIBXV\
IZMXFSJXLIKEGAEWHEPSWYSWIWIEVXLISXLIVXLIRGEPIRQIVIIBGIIHMWYPFLEVHEWHYPSRRFQMXLE\
PPXLIECCIEVEWGISJKTVWMRLIHYSPHXLIQIMYLXSJXLIMWRIGXQEROIVFVIZEVAEKPIEWHXEAMWYEPP\
XLMWYRMWXSGSWRMHIVEXMSWMGSTPHLEVHPFKPEZINTCMXIVJSVLMRSCMWMSWVIRCIGXMWYMX"


UNSORTED_ENG_FREQ = [('A', 8.55), ('B', 1.60), ('C',3.16), ('D', 3.87), ('E', 12.1),
            ('F', 2.18), ('G', 2.09), ('H', 4.96), ('I', 7.33), 
            ('J', 0.22), ('K', 0.81), ('L', 4.21), ('M', 2.53),
            ('N', 7.17), ('O',7.47), ('P',2.07), ('Q', 0.10),
            ('R', 6.33), ('S', 6.73), ('T', 8.94), ('U', 2.68),
            ('V', 1.06), ('W', 1.83), ('X',0.19), ('Y',1.72), ('Z', 0.11)
            ]

ENG_FREQ = sorted(UNSORTED_ENG_FREQ, key=lambda item:item[1], reverse=True)

ENG_BIGRAM_FREQ = [('TH',2.71), ('HE', 2.33), ('IN', 2.03), ('ER', 1.78),
                   ('AN', 1.61), ('RE', 1.41), ('ES', 1.32), 
                   ('ON', 1.32), ('ST', 1.25), ('NT', 1.17),
                   ('EN', 1.12), ('AT', 1.12), ('ED', 1.08), ('ND', 1.07),
                   ('TO', 1.07), ('OR', 1.06), ('EA', 1.00),
                   ]

ENG_TRIGRAM_FREQ = [('THE',1.81), ('AND', 0.73), ('ING', 0.72), ('ENT', 0.42),
                   ('ION', 0.42), ('HER', 0.36), ('FOR', 0.34), ('THA', 0.33),
                   ('NTH', 0.33),('INT', 0.32),('ERE', 0.31),('TIO', 0.31), ('TER', 0.30),
                   ('EST', 0.28), ('ERS', 0.28)
                   ]

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def get_lett_freq(txt):
    """
    txt is a string, all caps, no spaces or punctuation
    returns a list of tuples formatted as ENG_FREQ representing the percentage
    letter frequencies in txt, sorted descending
    """
    
    # convert txt to upper case
    txt = txt.upper()
    
    tot = len(txt)
    
    # compile a dictionary of letter counts 
    ret=[]
    
    for letter in ALPHABET:
        freq = 100*( txt.count(letter) )/tot  # letter freq as percentage
        
        ret.append( (letter, round(freq, 2)) )
        
    ret = sorted(ret,  key=lambda item:item[1], reverse=True)   
    return ret
        

def get_ngram_freq(txt, n):
    """ txt is a string, all caps, no spaces or punctuation
        (that is, containing only chars in ALPHABET)
        n is the number of sequential letters to consider, eg
        n=1 for single letters, n=2 for digrams, n=3 for trigrams
        
        returns a list of tuples ('ngram', int), formatted as ENG_LETTER_FREQ
        the percentage n-gram frequencies in txt, sorted descending
    """
    d = {}
    
    assert len(txt) >= n  # message must have at least n letters
    


    ## accumulate ngram counts    
    for i in range( len(txt)-n+1 ):
        ngram = txt[i:i+n]
        
        if ngram not in d:
            d[ngram] = 0
        d[ngram]+=1
        
    ## turn occurrence counts into frequencies
    
    tot = len(txt) - n + 1  # tot number of mgrams in msg 
    
    for ngram in d:
        freq = round( 100*(d[ngram] / tot), 2 ) 
        d[ngram] = freq

        
    ## turn them into sorted list of tuples
    ngrams = d.items() 
    ngrams = sorted(ngrams,  key=lambda x:x[1], reverse=True)   
    

    
    return ngrams

def gen_freq_table(ciph, eng):
    """
    ciph and eng are both lists of ('ngram', freq) tuples, respectively
    for a cipheretxt and for english text, sorted descending
    
    generates a string for printing them out in tabular form
   
    
    """    
    rows = min(len(ciph), len(eng))
    
    
    s = "cipher\t-->\tenglish\n"
    for i in range(rows):
        l1,f1 = ciph[i]
        l2,f2 = eng[i]
        
        row = l1 + " (" + str(f1) + ")  \t" + l2.lower() + " ("+str(f2) + ")\n"
        s = s+ row

    return s

def analyse(msg, sd={}):
    """
    msg is a string, allcaps, no spaces or punctuation, 
    that is the ciphertext to analyse
    
    sd is an optional substitution dictionary mapping 
    uppercase string ciphertext --> lowercase string english, 
    this is applied to the frequency tables
    """
    print("ciphertext: ", msg,"\n" )
    
    print("substitution dictionary", sd, "\n")

    
    ## get ciphertext letter frequencies & print freq table
    ciph_freq = get_lett_freq(msg)
    lett_table = gen_freq_table(ciph_freq, ENG_FREQ) 
    print( substitute(lett_table, sd) )

    
    ## get ciphertext bigram frequencies & print table 
    ciph_bigram_freq = get_ngram_freq(msg,2)  
    bigram_table = gen_freq_table(ciph_bigram_freq, ENG_BIGRAM_FREQ)
    print( substitute(bigram_table, sd) )
               
    ## get ciphertext trigram frequencies & print table
    ciph_trigram_freq = get_ngram_freq(msg,3)
    trigram_table = gen_freq_table(ciph_trigram_freq, ENG_TRIGRAM_FREQ) 
    print( substitute(trigram_table, sd) )

    print()
    print(substitute(msg, sd))          
           

                
def substitute(ciphtxt, d):
    """
    ciphtxt is a string, the (uppercase) ciphertext to decode
    d is a substition dictionary that maps 
    CIPHLETTER (uppercase)-- > ENGLETTER (lowercase)
    
    applies the dictionary and returns the result
    """
    # print("ciphertext is\n", ciphtxt)
    # print("applying substitution dictionary", d)
    result = ciphtxt
    
    for lett in d:
        result = result.replace(lett, d[lett])

        
    return result

    
   

      
analyse(CIPHER)