"""Functions for core 1, 2, 4 of Hybrid Cryptography."""
import random
import string
import requests
import core_one as c1
import math


def caesar_shift(letter, shift, alphabet): 
    """Caesar shifts a single character.
    OUTPUT: 'shifted_character'."""
    
    new_index = (alphabet.find(letter) + shift) % len(alphabet)   #finds the index of the character and shifts the index
    new_letter = alphabet[new_index]   #finds the character corresponding to the new index
    
    return new_letter
    
def caesar_invert_shift(letter, shift, alphabet): 
    """Inverts Caesar shift of single character.
    OUTPUT: 'inverted_shifted_character'."""
    
    inverse_shift = -shift   #takes minus shift and applies to caesar_shift
    new_letter = caesar_shift(letter, inverse_shift, alphabet)
    
    return new_letter
    
def caesar_encipher(plaintext, shift, alphabet): 
    """Caesar enciphers a whole message.
    OUTPUT: 'enciphered_message'."""
    
    enc_list = [caesar_shift(let, shift, alphabet) for let in plaintext]   #creates list of caesar shifted letters
    enc_string = ''.join(enc_list)   #turns list into a string

    return enc_string

def caesar_decipher(ciphertext, shift, alphabet): 
    """Caesar deciphers a whole message.
    OUTPUT: 'deciphered_message'."""
    
    dec_list = [caesar_invert_shift(let, shift, alphabet) for let in ciphertext]   #creates list of caesar shifted letters
    dec_string = ''.join(dec_list)   #turns list into a string

    return dec_string

def vigenere_encipher(plaintext, alphabet, key_length = 5):
    """Vigenere enciphers a message string.
    OUTPUT: ('enciphered message', 'key')."""
    
    # Want to generate a random key of lenth less than or equal to the message
    #select the length of the random key... (what is the optimal length?)
    key = ''.join(random.choice(alphabet) for i in range(key_length))   #generate the random key using characters from 'alphabet'
    
    ciphertext = ""   #create empty string
    for i in range(len(plaintext)):
        shift = alphabet.find(key[i % len(key)])   #find Caesar shift using key index
        ciphertext += caesar_shift(plaintext[i], shift, alphabet)   #Caesar shift the letter 
    
    return ciphertext, key

def vigenere_decipher(ciphertext, key, alphabet):
    """Vigenere deciphers a message string.
    OUTPUT: 'deciphered message'."""
    
    plaintext = ""   #create empty string
    for i in range(len(ciphertext)):
        shift = alphabet.find(key[i % len(key)])   #find Caesar shift
        plaintext += caesar_invert_shift(ciphertext[i], shift, alphabet)   #inverse the Caesar shift
        
    return plaintext

def url_to_text_utf8(url):
    '''Given a url for a text that is 'utf-8' encoded
    this function returns that text.'''
    
    response = requests.get(url)
    response.encoding = 'utf-8-sig'
    return response.text

def extract_text(text, alphabet):
    """Extracts the wanted characters from a text into a string.
    OUTPUT: 'extracted text'."""
    
    extracted = ""
    for let in text:
        if let in alphabet:
            extracted += let
    
    return extracted

def character_freq(text, alphabet, sort = False):
    """Takes a large text and characters of interest as input and returns
    a sorted dictionary of frequencies of the characters of interest in that text.
    OUTPUT: sorted dictionary of frequencies."""
    
    text = extract_text(text, alphabet)
    
    freq = []
    for let in alphabet:     #find the frequencies and append to a list
        count_i = text.count(let)   #count how many times that letter appears in the text
        freq.append(count_i/len(text))   #add to list
    
    freqdict = {}   
    for i in range(len(alphabet)):   #add frequencies to a dictionary
        freqdict.update({alphabet[i]: freq[i]})
    
    if sort == True:
        return sorted(freqdict.items(), key=lambda x:x[1])
    else:
        return freqdict

def find_shift(original_letter, new_letter, alphabet):
    """Finds the Ceasar shift given a letter from before and after shift.
    OUTPUT: shift."""
    
    shift = alphabet.index(new_letter) - alphabet.index(original_letter)   #difference of letter indexes
    
    return shift

def crack_caesar(ciphertext, alphabet, english_text, three_attempts = False):
    """Takes a Caesar encoded message and cracks it using letter
    frequency analysis without knowledge of the shift. Option to
    print 1 attempted crack or 3.
    OUTPUT: prints 1 or 3 attempted Caesar cracks."""
    
    known_freq = character_freq(english_text, alphabet, sort = True)   #create dictionaries for freq of letters in english text and in ciphertext
    cipher_freq = character_freq(ciphertext, alphabet, sort = True)
    
    length = len(alphabet)
    
    if three_attempts == True: 
        for i in range(3):
            shift = find_shift(str((known_freq[length-1])[0]), str((cipher_freq[length-1-i])[0]), alphabet)   #find the shift according to most freq letters
            plaintext = caesar_decipher(ciphertext, shift, alphabet)   #decipher using this shift
            print(plaintext)   #print deciphered message
            print(' ')
        return None
    
    else:
        shift = find_shift(str((known_freq[length-1])[0]), str((cipher_freq[length-1])[0]), alphabet)
        plaintext = caesar_decipher(ciphertext, shift, alphabet)
        return plaintext

def hybrid_send(plaintext, recipient_public, alphabet, key_length = 5):
    """Takes plaintext and RSA public keys and hybric encrypts a message using the core 4 algorithm.
    OUTPUT: ('vig message', 'RSA encrypted vig keys')."""
    
    vig_message, vig_key = vigenere_encipher(plaintext, alphabet, key_length = 5)   #encipher message and generate vig key
    
    no_slices = (len(vig_key)//60) + 1  #number of slices
    keys = []
    for i in range(no_slices):
        keys.append(vig_key[i*60:(i+1)*60])   #take out slices of length 60
    
    for i in range(len(keys)):
        keys[i] = c1.convert_to_integer(keys[i])   #convert each slice to integer form
        keys[i] = pow(keys[i], recipient_public[1], recipient_public[0])   #RSA encrypt each slice 
        
    keys = tuple(keys)   #convert to tuple
    
    return vig_message, keys

def hybrid_recieve(ciphertext, keys_tuple, my_private, my_public, alphabet):
    """Takes ciphertext, keys tuple and RSA keys and deciphers according to core 4 method of hybrid encryption.
    OUTPUT: 'plaintext'."""
    
    keys = list(keys_tuple)
    vig_key = ""
    for i in range(len(keys)):
        keys[i] = pow(keys[i], my_private, my_public[0])   #convert to integer
        keys[i] = c1.convert_to_text(keys[i])   #convert to vig key
        vig_key += keys[i]   #concatenate key back together
        
    plaintext = vigenere_decipher(ciphertext, vig_key, alphabet)
    
    return plaintext



def two_grams():
    """Generates all the 2-grams excluding repeated letters.
    OUTPUT: 'two_grams'."""
    
    two_gram = []
    for i in range(65, 91):
        for j in range(65, 91):
            if i != j:   #no double letters i.e. 'AA'
                two_gram.append(str(chr(i)) + str(chr(j)))   #constructed all of 25 X 26 2-grams
    
    return two_gram

def number_grams(english_text, alphabet):   #simply a-z for now...
    """Takes large extracted text and returns a dictionary of alphabet with 
    how many two grams each letter should be assigned to.
    OUTPUT: dictionary."""
    
    options = 650 #len(alphabet) * (len(alphabet)-1)   #all possible 2-grams
    
    dictionary = character_freq(english_text, alphabet)
    no_grams = {}
    for let in alphabet:
        no_grams[let] = math.floor(options * dictionary[let])
        
    return no_grams

def random_allocation(no_grams, alphabet):
    """Takes dictionary (from function 'number_grams'), all possible 2-grams
    and the alphabet to be encoded and returns a dictionary corresponding to
    strings that contain the set of encoding 2-grams for each letter of the alphabet.
    OUTPUT: dictionary."""
    
    two_gram = two_grams()
    
    options = 650 #len(alphabet) * (len(alphabet)-1)   #all possible 2-grams (minus repeats such as 'AA', 'BB,...')
    gram_dict = {}
    used = ""   #ensure no 2-gram used twice
    
    for let in alphabet:
        grams = ""
        
        while len(grams) < no_grams[let]*3:   #fill the string of 2-grams until it has the right amount 
            index = random.randrange(options)
            
            if (two_gram[index] + " ") not in used:
                grams += two_gram[index] + " "
                used += two_gram[index] + " "
        
        gram_dict[let] = grams
        
    return gram_dict

def encoding_info(gram_dict, alphabet, divide = "-"):
    """Returns the encoding information for 2-gram letter frequency masking.
    OUTPUT: 'string'."""
    
    info = ""
    for let in alphabet:
        info += gram_dict[let] + divide
    return info

def encoding(plaintext, no_grams, gram_dict, alphabet):
    """Encodes text by randomly selecting a 2-gram from the set of options previously determined.
    OUTPUT: 'encoded_text'."""
    
    encoded_text = ""
    for let in plaintext:
        index = random.randrange(no_grams[let])   #choose a random 2-gram from selection
        gram = (gram_dict[let])[index*3:index*3+3]   #find that 2-gram
        encoded_text += gram[:2]
        
    return encoded_text

def decoding(encoded_text, gram_dict, alphabet):
    """Decodes text using gram_dict to retrieve the original text.
    OUTPUT: 'decoded_text'."""
    
    decoded = ""
    for i in range(len(encoded_text)//2):
        for let in alphabet:
            if (encoded_text[i*2:i*2+2] + " ") in gram_dict[let]:
                decoded += let
    
    return decoded

def hybrid_send_v2(plaintext, recipient_public, english_text, alphabet):
    """Takes plaintext and encodes it with 2-gram mapping and then RSA and hybrid
    encrypts the message using the core 4 algorithm.
    OUTPUT: ('vig message', 'RSA encrypted vig keys -- encoding info')."""
    
    no_grams = number_grams(english_text, alphabet)
    gram_dict = random_allocation(no_grams, alphabet)   #create dictionaries for encoding
    plaintext = encoding(plaintext, no_grams, gram_dict, alphabet)   #do the encoding
    info = encoding_info(gram_dict, alphabet, divide = "-")   #encoding information
    
    vig_message, vig_key = vigenere_encipher(plaintext, alphabet)   #encipher message and generate vig key
    vig_key += "--" + info   #add encoding info to vig key
    
    
    no_slices = (len(vig_key)//60) + 1  #number of slices
    keys = []
    for i in range(no_slices):
        keys.append(vig_key[i*60:(i+1)*60])   #take out slices of length 60
    
    for i in range(len(keys)):
        keys[i] = c1.convert_to_integer(keys[i])   #convert each slice to integer form
        keys[i] = pow(keys[i], recipient_public[1], recipient_public[0])   #RSA encrypt each slice 
        
    keys = tuple(keys)   #convert to tuple
    
    return vig_message, keys

def hybrid_recieve_v2(ciphertext, keys_tuple, my_private, my_public, alphabet):
    """Takes ciphertext, keys tuple and encoding info and RSA keys and deciphers
    according to core 4 method of hybrid encryption and 2-gram encoding.
    OUTPUT: 'plaintext'."""
    
    keys = list(keys_tuple)
    vig_key = ""
    for i in range(len(keys)):
        keys[i] = pow(keys[i], my_private, my_public[0])   #convert to integer
        keys[i] = c1.convert_to_text(keys[i])   #convert to vig key
        vig_key += keys[i]   #concatenate key back together
        
    keys = vig_key
    index = keys.find("-")
    vig = keys[:index]
    
    enc = keys[index+2:]   #find encoding info
    gram_dict = {}   #create dictionary for encoding
    for let in alphabet:
        index = enc.find("-")   #find info for each letter
        gram_dict[let] = enc[:index]   #input into dictionary
        enc = enc[index+1:]   #update encoding info string
    
    plaintext = vigenere_decipher(ciphertext, vig, alphabet)
    decoded_text = decoding(plaintext, gram_dict, alphabet)
    
    return decoded_text

