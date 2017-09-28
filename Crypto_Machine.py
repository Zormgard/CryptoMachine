import os
import random
import glob
import struct
import smtplib
import time
import requests

from multiprocessing import Pool
from simplecrypt import encrypt, decrypt

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


# IV = initialization vector


def padding(size):
    return size + b"\0" * (AES.block_size - len(size) % AES.block_size)

def encrypt(message, key, key_size=256):

	""" Kryptere en fil ved at bruge (CBC mode) med en givent nøgle.

        Nøglen:
            Krypterings nøglen - en string som skal være på inten 
            16, 24 or 32 bytes lange. Længere nøgler
            er mere sikre.

        in_filename:
            Navnet på den fil som skal krypteres

        out_filename:
            Hvis filnavnet ikke findes, '<in_filename>.enc' vil blive brugt.

        chunksize:
            sætter størelsen på den "chunk" som funktionen bruger
            til at læse og kryptere filen. 
            Større chunk størelser kan for nogle filer eller maskiner
            være hurtigere. Chunksize skal kunne divideres med 16. """


    message = padding(message)
    IV = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    return IV + cipher.encrypt(message)

def decrypt(ciphertext, key):
	# IV = initialization vector
    IV = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(IV)
    return plaintext.rstrip(b"\0")


def encrypt_file(file_name, key):
                         #'rb' = read block
    with open(file_name, 'rb') as file_open:
        plaintext = file_open.read()
    encrypt_file = encrypt(plaintext, key)
                                           #'wb' = write block
    with open(file_name + ".enc", 'wb') as file_open:
        file_open.write(encrypt_file)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as file_open:
        ciphertext = file_open.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as file_open:
        file_open.write(dec)


key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'

#encrypt_file('/home/lasse/Skrivebord/file.txt', key)


decrypt_file('/home/lasse/Skrivebord/file.txt', key)