__author__ = 'Michael Aquilina'

__desc__ = """
My attempt at writing some cryptographic block ciphers for many time key use. Makes use
of PyCrypto - specifically the AES functionality.

SPOILER: I am aware i should not be implementing ciphers myself for use in production - this code is
my way of learning how to use PyCrypto and how the inner workings of certain cipher structures work.

Please do not rely on the security of this code for use in production!
"""

from Crypto.Cipher import AES
from crypto_functions import hex_to_ascii, ascii_to_hex, strxor

import math
import os


def _pad(text, block_size):
    """
    Performs padding on the given plaintext to ensure that it is a multiple
    of the given block_size value in the parameter. Uses the PKCS7 standard
    for performing paddding.
    """
    no_of_blocks = math.ceil(len(text)/float(block_size))
    pad_value = int(no_of_blocks * block_size - len(text))

    if pad_value == 0:
        return text + chr(block_size) * block_size
    else:
        return text + chr(pad_value) * pad_value


def aes_ctr_encrypt(key, plaintext, block_size=16):
    """
    Encrypts the given plaintext with AES with counter mode
    as a mode of operation. Uses a block size of 16 by default if
    not specified in the parameters.
    """
    cipher = AES.new(key)
    
    no_of_blocks = int(math.ceil(len(plaintext) / float(block_size)))
    cipher_blocks = []
    
    # Generate the IV from urandom
    IV = ascii_to_hex(os.urandom(16))
    
    for i in xrange(0, no_of_blocks):
        # No padding needed
        m = plaintext[i * block_size: (i + 1) * block_size]
        chain = cipher.encrypt(hex_to_ascii(IV + i))
        
        cipher_blocks.append(strxor(chain, m))
        
    # Return IV appended to the generated cipher blocks
    return hex_to_ascii(IV) + ''.join(cipher_blocks)


def aes_ctr_decrypt(key, ciphertext, block_size=16):
    """
    Decrypts the given ciphertext with the given key using AES CTR
    (Randomized counter mode) and returns the result in the form of
    a string.
    """
    cipher = AES.new(key)

    no_of_blocks = int(math.ceil(len(ciphertext) / float(block_size)))
    message_blocks = []

    # Retrieve the IV from the first block
    IV = ascii_to_hex(ciphertext[0:block_size])

    for i in xrange(1, no_of_blocks):
        c = ciphertext[i * block_size: (i + 1) * block_size]

        chain = cipher.encrypt(hex_to_ascii(IV + i - 1))
        m = strxor(chain, c)

        message_blocks.append(m)

    return ''.join(message_blocks)


def aes_cbc_encrypt(key, plaintext, block_size=16):
    """
    Encrypts the given plaintext with AES with cipher block chaining
    as a mode of operation. Uses a block size of 16 by default if
    not specified in the parameters.
    """

    cipher = AES.new(key)

    # Calculate the number of blocks required
    no_of_blocks = int(math.ceil(len(plaintext) / float(block_size)))
    cipher_blocks = []

    # Pad the plaintext as is necessary
    plaintext = _pad(plaintext, block_size)

    # Random IV
    IV = os.urandom(block_size)
    prev = IV

    for i in xrange(no_of_blocks):
        block = plaintext[i * block_size: (i + 1) * block_size]

        block = strxor(block, prev)

        ct = cipher.encrypt(block)
        prev = ct

        cipher_blocks.append(ct)

    # Return IV appended with the cipher blocks
    return IV + ''.join(cipher_blocks)


def aes_cbc_decrypt(key, ciphertext, block_size=16):
    """
    Decrypts the given ciphertext with the given key using AES CBC
    (Cipher Block Chaining) and returns the result in the form of
    a string.
    """
    cipher = AES.new(key)

    # Calculate the number of blocks
    no_of_blocks = int(math.ceil(len(ciphertext) / float(block_size)))
    message_blocks = []

    # Store the IV as the start
    prev = ciphertext[0:block_size]

    for i in xrange(1, no_of_blocks):
        c = ciphertext[i * block_size: (i + 1) * block_size]

        chain = prev   # Current chain value to xor with
        prev = c       # store previous ciphertext value for next iteration

        c = cipher.decrypt(c)
        c = strxor(chain, c)

        message_blocks.append(c)

    # Using PKCS7 for padding
    result = ''.join(message_blocks)
    return result.rstrip(result[-1:])


if __name__ == '__main__':
    # Run Test Suite to ensure Integrity of code
    # Ensure the padding algorithm works as expected
    TEST_TEXT = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt'

    assert _pad(TEST_TEXT[:16], 16) == TEST_TEXT[:16] + (chr(16) * 16)    # 16 bytes
    assert _pad(TEST_TEXT[:26], 16) == TEST_TEXT[:26] + (chr(6) * 6)    # 26 bytes
    assert _pad(TEST_TEXT[:12], 16) == TEST_TEXT[:12] + (chr(4) * 4)    # 12 bytes

    # Ensure Integrity of message is maintained when encrypting and decrypting
    KEY = 'Password10234125'
    assert aes_cbc_decrypt(KEY, aes_cbc_encrypt(KEY, TEST_TEXT)) == TEST_TEXT
    assert aes_ctr_decrypt(KEY, aes_ctr_encrypt(KEY, TEST_TEXT)) == TEST_TEXT

    # ============================================== #

    import argparse

    parser = argparse.ArgumentParser(description='Encrypt or Decrypt using the AES cipher.')
    parser.add_argument('--key', '-k', required=True, help='The key to use to perform the encryption or decryption.')
    parser.add_argument('--text', '-t', required=True, help='The plaintext or ciphertext to use the AES algorithm on.')
    parser.add_argument('--block-size', '-b', default=16, choices=(16, 32, 64), help='The size of the blocks to make use of in bytes.')
    parser.add_argument('--mode', '-m', default='encrypt', choices=('encrypt', 'decrypt'), help='Specify whether the tool will decrypt or encrypt the input text.')

    args = parser.parse_args()

    if args.mode == 'encrypt':
        print aes_cbc_encrypt(args.key, args.text, args.block_size).encode('hex')
    else:
        print aes_cbc_encrypt(args.key, hex('0x' + args.text.decode('hex')), args.block_size)
