import random
import string


def caesar_encrypt(plaintext,s):
    """Takes plaintext input and s-shifts to encipher.
    Preserves upper/lower cases."""
    
    result = ""

    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():

            if (char.isupper()):
                result += chr((ord(char) + s - 65) % 26 + 65)
     
            else:
                result += chr((ord(char) + s - 97) % 26 + 97)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, s):
    """Takes ciphertext input and shifts it back to original plaintext.
    Preserves upper/lower cases."""
    
    result = ""

    for i in range(len(ciphertext)):
        char = ciphertext[i]

        if (char.isupper()):
            result += chr((ord(char) - s - 65) % 26 + 65)
     
        else:
            result += chr((ord(char) - s - 97) % 26 + 97)
    return result
    
def random_key(plaintext):
    """Generates a random Vigenere key shorter than the length of the plaintext."""
    
    keyword = []
    n = len(plaintext)
    a = randrange(5,n+1)
    for i in range(a + 1):
        b = randrange(0,2)
        if b < 1:
            n = randrange(65,91)
            keyword.append(chr(n))
        else:
            n = randrange(97,123)
            keyword.append(chr(n))               
    return keyword         
        

def extend_key(plaintext, key):
    """Takes plaintext and key and repeats key until matching the length of the plaintext."""
    
    key = list(key)
    if len(plaintext) == len(key):
        return("".join(key))
    else:
        for i in range(len(plaintext) - len(key)):
            key.append(key[i % len(key)])
    return("".join(key))
    
    
def vig_encrypt(plaintext, key):
    """Vigenere encrypts the plaintext using the key given
    (only suitable for all upper case letters)."""
    key = key.upper()
    cipher_text = []
    for i in range(len(plaintext)):
        char = plaintext[i]   
        char_num = ord(char.upper())-65
        key_num = ord(key[i%len(key)]) - 65
        shift_num = (char_num+key_num) % 26
        shift_char = chr(shift_num + 65)
        if char.islower():
            shift_char = char.lower()
        cipher_text.append(shift_char)
    return ("".join(cipher_text))    
        
def vig_decrypt(ciphertext, key):
    """Vigenere decrypts the ciphertext with key given
    (only suitable for all upper case letters)."""
    key = key.upper()   
    orig_text = []
    for i in range(len(ciphertext)):
        char = ciphertext[i]   
        char_num = ord(char.upper()) - 65
        key_num = ord(key[i%len(key)]) - 65
        shift_num = (char_num - key_num) % 26
        shift_char = chr(shift_num + 65)
        if char.islower():
            shift_char = char.lower()
        orig_text.append(shift_char)
    return("" . join(orig_text))

    

def url_to_text_utf8(url):
    '''Given a url for a text that is 'utf-8' encoded
    this function returns that text.'''
    
    response = requests.get(url)
    response.encoding = 'utf-8-sig'
    return response.text


def extract_text(text):
    """Takes a large text and extracts the alphabetic content from it
    (lower case only)."""
    text = list(text)
    alph_text = []
    count = 0
    for i in range(len(text)):
        if 64 < ord(text[i]) < 92 or 96 < ord(text[i]) < 123:
            alph_text.append(text[i])
            count += 1
    
    alph_text = (str(alph_text)).lower()
            
    return alph_text, count   #.lower() converts all letters to lower case only
            


def isprime_basic(n,verbose=False): 
    '''
    Checks whether the argument n is a prime number using a brute force 
    search for factors between 1 and n. We made it verbose here for 
    illustration. (I.e. it prints out its results.)
    '''
    # First, 1 is not prime.
    if n == 1:
        return False
    # If n is even then it is only prime if it is 2
    if n % 2 == 0: 
        if n == 2: 
            return True
        else:
            if verbose:
                print("{} is not prime: {} is a factor. ".format(n,2))
            return False
    # So now we can consider odd numbers only. 
    j = 3
    rootN = n**0.5
    # Now check all numbers 3,5,... up to sqrt(n)
    while j <= rootN: 
        if n % j == 0:
            if verbose:
                print("{} is not prime: {} is a factor.".format(n,j))
            return False
        j = j + 2
    if verbose:
        print("{} is prime.".format(n))
    return True         
        
def basic_prime_generator(order=1e9):
    """This is a prime number generator. It is called basic because it relies on the basic (slow) primality test.
    Output will be a random prime between order and 2*order."""
    n=random.randint(order,2*order)
    while not isprime_basic(n):
        n=random.randint(order,2*order)
    return n

def RSA_key_generator1(bit_length):
    """This will generate RSA keys using primes p, q of bit length inputted.
    This is a version of the private key. The output is ((PublicKey),PrivateExp,Factorisation)."""
    ## Generate two large primes.
    p=random_prime(bit_length)
    q=random_prime(bit_length)
    N=p*q
    
    ## Next, get phi and use it to get a public and private exponent.
    phi=(p-1)*(q-1)
    ## Choose encryption exponent e randomly between 1 and p and q.
    e=random.randint(1,min(p,q))
    ## It must be coprime to phi though:    
    while gcd(e,phi) >1:
        e=random.randint(1,min(p,q))
    
    ## Finally, get d from the extended Euclid's algorithm.
    (g,d,x) = gcd_ext(e,phi)
    
    ## Then return the keys.
    return ((N,e),d%phi,{p:1,q:1})

def char_to_byte(char): 
    """
    Returns the 8 bit binary representation (padded with 
    leading zeros with necessary) of ord(char), i.e. of 
    the order of the input character char. 
    """
    byte_string = bin(ord(char))[2:]     # The order of char as a binary string 
    num_zeros = 8 - len(byte_string)     # The number of zeros needed to pad out byte_string
    for i in range(num_zeros):           # Now pad out byte_string with num_zeros many zeros
        byte_string = '0' + byte_string  # to obtain the 8-bit binary representation
    return byte_string  

def convert_to_integer(text,verbose=False): 
    """
    Returns an integer that encodes the input string text. 
    Each character of text is encoded as a binary string of 
    8 bits. These strings are concatenated with a leading 1
    and the resulting binary string is converted into the 
    returned integer.
    """
    bin_string = '1'
    for letter in text: 
        bin_string = bin_string + char_to_byte(letter)
    if verbose: 
        print("The binary representation of this message is:")
        print(bin_string)
    return int(bin_string,2)

def convert_to_text(number): 
    """ 
    Returns a string that is the decoding of the input integer number.
    This is done by converting number to a binary string, removing the 
    leading character '1', slicing out each 8 bit substring consecutively,
    converting each such string to the character it encodes and concatenating
    these characters to obtain the decoded string.    
    """
    # Remove '0b1' from the string 
    bin_string = bin(number)[3:] 
    text = ''                           
    length = len(bin_string)
    for i in range(0,length,8):  
        # Pick out binary strings, 8 bits at a time
        byte_string = bin_string[i:i+8]   
        # Convert byte_string to a character before 
        # appending it to text 
        text = text + chr(int(byte_string,2))  
    return text

def generate_shift(plaintext):
    n = len(plaintext)
    s = randrange(1,n+1)
    return s

def gcd_ext(a,b):
    """Outputs (gcd,x,y) such that gcd=ax+by."""
    if not(a%1 ==0 and b%1==0):                         #Reject if trying to use for non-integers
        print( "Need to use integers for gcd.")
        return None
    
    
    if a == 0:                                          #Base case is when a=0.
        return (abs(b), 0, abs(b)//b)                   #Then gcd =|b| and is 0*a+1*b or 0*a-1*b. Use abs(b)//b
    
    
    else:
        quot=b//a                                       #The rule is that g=gcd(a,b)=gcd(b%a,a).
                                                        #Let b=qa+r where r=b%a
        g, x, y = gcd_ext(b%a, a)                       #And if  g=x1*r + y1*a then since r=b-qa
        return (g, y - quot * x, x)                     #We get g = a*(y1-q*x1)+x1*b.
                                                        #So x=y1-q*x1 and y=x1.
        
def gcd(a,b):
    """Returns the greatest common divisor of integers a and b using Euclid's algorithm.
    The order of a and b does not matter and nor do the signs."""
    if not(a%1 ==0 and b%1==0):
        print( "Need to use integers for gcd.")
        return None
    if b==0:
        return abs(a)                           #Use abs to ensure this is positive
    else:
        return gcd(b,a%b)

def random_prime(bit_length):
    '''
    Returns a cryptographically secure random numbber 
    of bit_length many (binary) bits 
    '''
    while True:
        p = SystemRandom().getrandbits(bit_length)  
        # Check whether p is a prime of the right bit length
        if p >= 2**(bit_length-1):
            if is_prime(p):
                return p
def random_prime(bit_length):
    '''
    Returns a cryptographically secure random numbber 
    of bit_length many (binary) bits 
    '''
    while True:
        p = SystemRandom().getrandbits(bit_length)  
        # Check whether p is a prime of the right bit length
        if p >= 2**(bit_length-1):
            if is_prime(p):
                return p 
    
def rsa_private_key(bit_length):
    '''
    Given input bit_length returns a private RSA key (p,q) where 
    both p and q are primes with bit_length number of (binary) bits. 
    '''
    p = random_prime(bit_length)
    q = random_prime(bit_length)
    return (p,q) 

def rsa_public_key(p,q, e = 65537):
    '''
    Given input (p,q,e) returns the RSA public key 
    from the two prime numbers p and q and auxiliary 
    exponent e. If only (p,q) input, e = 65537 is used.
    '''
    N = p * q
    return (N,e)

def hybrid_send(plaintext, recipient_public):
    
    #vig encrypting message and generating vig key
    key = random_key(plaintext)
    key = extend_key(plaintext, key)
    cyphertext = vig_encrypt(plaintext, key)
    
    
    #slicing vig key
    n = len(key)
    x = (n//63) + 1 #integer division 63 into len(key), +1 for the remaining values  (assuming 512 bit primes used)
    key1 = []
    while n > x:   # x = max length for RSA encryption
        key1.append(key[:x])
        n -= x
    
    #RSA encypting vig key
    key_integer = []
    rsa_key = []
    for i in range(len(key1)):   #take each section of the key
        key_integer.append(c1.convert_to_integer(key1[i]))   #convert each section to integer 
        rsa_key.append(pow(key_integer[i], recipient_public[1], recipient_public[0]))   #RSA encrypt each section of key
                           #left with list of encrypted vigenere key sections
     
    rsa_tuple = tuple(rsa_key)
                           
    return cyphertext, rsa_tuple

def hybrid_recieve(cyphertext, key, my_private, my_public):
    
    key = list(key)   #convert tuple into list
    vig_key = []
    for i in range(len(key)):
        key_integer = pow(key[i], my_private, my_public[0])   #convert each slice of key back to integer
        vig_key.append(c1.convert_to_text(key_integer))   #convert each integer back to text (vig key)
    
    total_key = []
    for j in range(len(vig_key)):
        for k in range(len(vig_key[j])):
            total_key.append(vig_key[j][k])   #append slices of key into one list
    
    plaintext = c1.vig_decrypt(ciphertext, total_key)   #vig decrypt cyphertext with key
    
    return plaintext

def vig_encrypt2(plaintext, key):
    """Updated Vigenere cypher taking key of any length and plaintext/key
    of upper and lower case letters and returning cyphertext of upper and
    lower case letters (capitalisation not preserved).
    Output: cyphertext"""
    
    letters = sorted(string.ascii_letters + str(' '))
    ASCII = {}
    for i in range(len(letters)):
        ASCII[ord(letters[i])] = letters[i]
    ASCII = sorted(ASCII.values(), key=lambda x:x[0])
    
    cipher_text = []
    for i in range(len(plaintext)):
        x = (letters.index(plaintext[i]) + letters.index(key[i%len(key)])) % len(letters)   # index of 'letters' corresponding to cyphertext letter
        y = ASCII[x][0]
        cipher_text.append(y)
            
    return("" . join(cipher_text))

def vig_decrypt2(ciphertext, key):
    """Updated Vigenere decryption working for any combination of
    upper/lower case letters (capitalisation not preserved).
    Output: plaintext"""
    
    letters = sorted(string.ascii_letters + str(' '))
    ASCII = {}
    for i in range(len(letters)):
        ASCII[ord(letters[i])] = letters[i]
    ASCII = sorted(ASCII.values(), key=lambda x:x[0])
    
    orig_text = []
    for i in range(len(ciphertext)):
        x = (letters.index(ciphertext[i]) - letters.index(key[i%len(key)]) + len(letters)) % len(letters)
        y = ASCII[x][0]
        orig_text.append(y)
    
    return("" . join(orig_text))
    
    
from random import SystemRandom
from miller_rabin import is_prime

# Find a cryptographically secure random number of bitlength many bits. 
def random_prime(bit_length):
    '''
    Returns a cryptographically secure random numbber 
    of bit_length many (binary) bits 
    '''
    while True:
        p = SystemRandom().getrandbits(bit_length)  
        # Check whether p is a prime of the right bit length
        if p >= 2**(bit_length-1):
            if is_prime(p):
                return p
            
def hybrid_send1(plaintext, recipient_public):
    """Follows the core 4 hybrid encryption algorithm and
    vigenere encrypts the plaintext, then converts the vigenere key
    into an integer and then RSA encrypts the key.
    WARNING: ASSUMES 512 bit primes p, q
    Output: (cyphertext, rsa_tuple)"""
    
    #vig encrypting message and generating vig key
    key = random_key(plaintext)
    cyphertext = vig_encrypt2(plaintext, key)
    
    
    #slicing vig key
    n = len(key)
    x = 63   #(n//63) + 1 #integer division 63 into len(key), +1 for the remaining values  (assuming 512 bit primes used)
    key1 = []
    while n > 0:   # x = max length for RSA encryption
        if x >= n:
            key1 = key
        else:
            key1.append(key[:x])
        n -= x
    
    
    #RSA encypting vig key
    key_integer = []
    rsa_key = []
    for i in range(len(key1)):   #take each section of the key
        key_integer.append(convert_to_integer(key1[i]))   #convert each section to integer 
        rsa_key.append(pow(key_integer[i], recipient_public[1], recipient_public[0]))   #RSA encrypt each section of key
                           #left with list of encrypted vigenere key sections
     
    rsa_tuple = tuple(rsa_key)
                           
    return cyphertext, rsa_tuple

def hybrid_recieve1(cyphertext, key, my_private, my_public):
    """Follows the core 4 hybrid encryption algorithm and RSA
    decrypts the tuple and converts to text, then decrypts the
    vigenere cypher using the decrypted key.
    WARNING: ASSUMES 512 bit primes p, q
    Output: (plaintext)"""
    
    key = list(key)   #convert tuple into list
    vig_key = []
    for i in range(len(key)):
        key_integer = pow(key[i], my_private, my_public[0])   #convert each slice of key back to integer
        vig_key.append(convert_to_text(key_integer))   #convert each integer back to text (vig key)
    
    total_key = []
    for j in range(len(vig_key)):
        for k in range(len(vig_key[j])):
            total_key.append(vig_key[j][k])   #append slices of key into one list
            
    
    plaintext = vig_decrypt2(cyphertext, total_key)   #vig decrypt cyphertext with key
    
    return plaintext