from crypto_functions import is_valid_text, strxor, hex_to_ascii, ascii_to_hex


def run_crypto_test_suite():
    # UNIT TESTS TO MAKE SURE OUR FUNCTIONS ARE WORKING!
    A = 'hello world23!!'
    B = 'password1232332'
    C = 0x48656c6c6f20576f726c64   # Hello World

    assert strxor(strxor(A, B), B) == A, 'strxor integrity invalid, %s!=%s' % (A, strxor(strxor(A, B), B))
    assert strxor(strxor(B, A), B) == A
    assert strxor(strxor(A, B), A) == B

    assert hex_to_ascii(ascii_to_hex(A)) == A, 'Integrity of hex_to_ascii and ascii_to_hex not valid'
    assert ascii_to_hex(hex_to_ascii(C)) == C

    assert not is_valid_text('$!@#!@#'), 'Invalid attempt_text is passing'
    assert not is_valid_text(u'\xAE'), 'Invalid unicode attempt_text is passing'
    assert is_valid_text('Hello world'), 'Valid attempt_text is not passing'

    assert strxor(strxor('hello', 'THERE'), 'there') == 'HELLO'
    assert strxor(strxor('hello', 'THERE'), 'hELLO') == 'There'