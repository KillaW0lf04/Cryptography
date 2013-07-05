from Crypto.Cipher import AES
from crypto_functions import hex_to_ascii, ascii_to_hex, strxor

import math

def aes_ctr_encrypt(key, plaintext, block_size=16):
    pass

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
    pass

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


# CBC Encryptions
# Task 1
key = hex_to_ascii(0x140b41b22a29beb4061bda66b6747e14)
ciphertext = hex_to_ascii(
    0x4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81
)

print aes_cbc_decrypt(key, ciphertext)

# Task 2
key = hex_to_ascii(0x140b41b22a29beb4061bda66b6747e14)
ciphertext = hex_to_ascii(
    0x5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253
)

print aes_cbc_decrypt(key, ciphertext)

# CTR Encryptions
# Task 3
key = hex_to_ascii(0x36f18357be4dbd77f050515c73fcf9f2)
ciphertext = hex_to_ascii(
    0x69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329
)

print aes_ctr_decrypt(key, ciphertext)

# Task 4
key = hex_to_ascii(0x36f18357be4dbd77f050515c73fcf9f2)
ciphertext = hex_to_ascii(
    0x770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451
)

print aes_ctr_decrypt(key, ciphertext)
