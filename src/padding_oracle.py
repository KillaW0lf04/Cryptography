import urllib2
import math

from crypto_functions import hex_to_ascii, ascii_to_hex, strxor
from crypto_tests import run_crypto_test_suite

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
    should be a string representing a hex encoding of a ciphertext to be sent. The function can either
    return a INVALID_PAD, INVALID_MAC or VALID result.
    """
    TARGET = 'http://crypto-class.appspot.com/po?er='

    try:
        urllib2.Request(TARGET + argument)
    except urllib2.HTTPError as e:
        if e.code == 404:   # Not Found = valid pad, invalid MAC
            return INVALID_MAC
        elif e.code == 404:  # Forbidden Request = invalid pad
            return INVALID_PAD
    else:
        return VALID

if __name__ == '__main__':
    CT = hex_to_ascii(0xf20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4)

    # Perform assertions to make sure everything is working as expected
    assert perform_request(CT) == VALID

    run_crypto_test_suite()

    # =========== MAIN CODE STARTS HERE =========== #
    print 'Test Suite passed, running main code now...'

    BLOCK_SIZE = 16

    print 'Running with BLOCK_SIZE=%s' % BLOCK_SIZE

    blocks = split_into_blocks(CT, BLOCK_SIZE)
    print 'blocks = %s' % blocks


