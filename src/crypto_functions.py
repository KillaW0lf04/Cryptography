from string import ascii_letters


def hex_to_ascii(value):
    hex_text = hex(value)[2:-1]
    
    if len(hex_text) % 2 == 1:
        return ('0'+hex_text).decode('hex')
    else:
        return hex_text.decode('hex')


def ascii_to_hex(value):
    return int(value.encode('hex'), 16)


# Method used to generate the original ciphertexts
# xor two strings of different lengths
def strxor(a, b):
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def is_valid_text(attempt_text):
    for c in attempt_text:
        if c not in ascii_letters and c != ' ':
            return False
    
    return True
