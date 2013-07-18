"""
Solution i used to solve a cryptography assignment for a course i took.

Takes a website which is vulnerable to padding oracle attacks and reveals
some target ciphertext by using said attack.

KNOWN BUG: when guessing the last message block, it will not be able to
distinguish padding as a correct guess. This has to be manually set in
known_message_blocks to work. e.g. 04040404 will be counted as an incorrect guess.
"""

import urllib2
import math
import sys

from crypto_functions import hex_to_ascii, strxor
from crypto_tests import run_crypto_test_suite

# Possible status codes that can be returned by perform_request()
UNKNOWN_ERROR = -1
INVALID_PAD = 1
INVALID_MAC = 2
VALID = 3


def split_into_blocks(text, block_size):
    block_count = int(math.ceil(len(text) / float(block_size)))
    blocks = []

    for i in xrange(block_count):
        blocks.append(text[i * block_size: (i + 1) * block_size])

    return blocks


def perform_request(argument):
    """
    Requests a result from the target URL for this attack code. The argument expected in the argument
    should be a string. The string will automatically be converted to a hex encoded value when performing
    the request to the server. The function can either return a INVALID_PAD, INVALID_MAC, VALID or
    UNKNOWN_ERROR result.
    """
    TARGET = 'http://crypto-class.appspot.com/po?er='
    argument = argument.encode('hex')

    try:
        urllib2.urlopen(TARGET + argument)
    except urllib2.HTTPError as e:
        if e.code == 404:   # Not Found = valid pad, invalid MAC
            return INVALID_MAC
        elif e.code == 403:  # Forbidden Request = invalid pad
            return INVALID_PAD
        else:
            return UNKNOWN_ERROR
    else:
        return VALID


def perform_padding_attack(block_list, attack_block_index, block_size, known_message_info=None):
    attack_block = block_list[attack_block_index]

    # If no known information is available, start from the beginning
    if known_message_info is None:
        message_block = chr(0) * block_size
    else:
        message_block = known_message_info

    for padding_index in xrange(1, block_size + 1):
        pad_value = chr(0) * (block_size - padding_index) + chr(padding_index) * padding_index

        char_index = block_size - padding_index
        if message_block[char_index] != chr(0):
            continue
        else:
            print 'PAD VALUE: %s' % pad_value.encode('hex')

        # Perform 1 of 256 guesses
        for guess in xrange(256):
            guess_value = chr(0) * char_index + chr(guess) + message_block[char_index + 1:]

            # Calculate the new value for the attack block
            attack_hex = strxor(pad_value, guess_value)
            block_value = strxor(attack_hex, attack_block)

            # Generate the output ciphertext block with the altered attack block
            output_blocks = block_list[:attack_block_index] + [block_value, block_list[attack_block_index + 1]]
            output = ''.join(output_blocks)

            result = perform_request(output)
            if result == INVALID_MAC:
                result_text = 'INVALID MAC'
            elif result == INVALID_PAD:
                result_text = 'INVALID PAD'
            elif result == VALID:
                result_text = 'VALID'
            else:
                result_text = 'UNKNOWN ERROR'

            print 'Guess=%s, PadIndex=%s, Result=%s, GuessHex=%s, MessageState=\'%s\'' % \
                  (guess, padding_index, result_text, guess_value.encode('hex'), message_block)
            if result == INVALID_MAC:
                message_block = guess_value
                print 'Guess %s was correct. Current message=\'%s\' (hex: %s)' % (guess, message_block, message_block.encode('hex'))
                break

            if guess == 255:
                print 'FATAL ERROR: Could not find a guess :('
                print 'Contents of message: %s (hex: %s)' % (message_block, message_block.encode('hex'))
                sys.exit(1)

    return message_block


if __name__ == '__main__':
    import os

    # Blocks of known information that can be skipped
    # Organise by block_index and known text (16 chars per block)
    # E.g. {1: 'This is text one', 2: chr(0) * 9 + ' seven '}
    # Where chr(0) is content in the block which has yet to be guessed
    known_message_blocks = {}

    # Ciphertext with which to perform the attack
    CT = hex_to_ascii(0xf20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4)

    # =========== RUN TEST SUITE ========== #
    INVALID_CT = os.urandom(64)

    assert perform_request(CT) == VALID, 'A known VALID request was reported as invalid!'
    assert perform_request(INVALID_CT) != VALID, 'An INVALID request was reported as valid!'
    # Create a test to check if INVALID_MAC and INVALID_PAD are correctly caught
    # use aes_tool.py to create ciphertext and then change values accordingly

    run_crypto_test_suite()

    # =========== MAIN CODE STARTS HERE =========== #
    print 'Test Suite passed, running main code now...'

    BLOCK_SIZE = 16

    print 'Running with BLOCK_SIZE=%s' % BLOCK_SIZE

    blocks = split_into_blocks(CT, BLOCK_SIZE)
    print 'blocks = %s' % blocks

    # Iterate through block list backwards
    for block_index in xrange(0, len(blocks) - 1):
        attack_block_index = block_index

        known_message_info = known_message_blocks.get(block_index, None)
        known_message_blocks[block_index] = perform_padding_attack(blocks, attack_block_index, BLOCK_SIZE, known_message_info=known_message_info)

        print known_message_blocks[block_index]

    # Generate the final result from the known message blocks
    result = ''.join(known_message_blocks.values())
    result = result.rstrip(result[-1:])  # Remove the padding bytes

    print 'BROKEN CIPHERTEXT: \'%s\'' % result
