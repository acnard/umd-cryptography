# -*- coding: utf-8 -*-
"""
Created on Sun Mar 27 15:19:14 2022

@author: Anna
"""

CIPHER = "OVDTHUFWVZZPISLRLFZHYLAOLYL"

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def decrypt(msg, k):
    """
    msg is a string, the ciphertext to decrypt
    k is an integer between 0 and 25 that is the shift key
    such that   k=0 maps A-->a, 
                k=1 maps A-->b,
                k=2 maps A-->c,
                k=25 maps A --> z
                
    NB by convention ciphertext is uppercase and plain text is lower case
                
    """
    
    plaintxt = ""
    
    for char in msg:
        i = ALPHABET.index(char)
       
        i_new = (i+k)%26
        
        plaintxt = plaintxt + ALPHABET[i_new].lower()
        
    return plaintxt

def test():
    print("cipher=", CIPHER)
    for k in range(26):
        print("\ntrying key ", k)
        print(decrypt(CIPHER, k))
             
        
    
        
    
    