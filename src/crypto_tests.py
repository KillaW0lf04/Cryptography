from crypto_functions import is_valid_text, strxor

def run_crypto_test_suite():
    # UNIT TESTS TO MAKE SURE OUR FUNCTIONS ARE WORKING!
    A = 'hello world23!!'
    B = 'password1232332'

    assert strxor(strxor(A, B), B) == A, 'strxor integrity invalid, %s!=%s' % (A, strxor(strxor(A, B), B))
    assert strxor(strxor(B, A), B) == A
    assert strxor(strxor(A, B), A) == B

    # assert hex_to_ascii(plaintext_hex) == test_text, 'Failed to xor back and forth with integrity (strxor failed)'
    # assert hex_to_ascii(ciphertext_hex ^ key_hex) == test_text, 'Failed to encrypt and decrypt with integrity.'

    assert not is_valid_text('$!@#!@#'), 'Invalid attempt_text is passing'
    assert not is_valid_text(u'\xAE'), 'Invalid unicode attempt_text is passing'
    assert is_valid_text('Hello world'), 'Valid attempt_text is not passing'

    assert strxor(strxor('hello', 'THERE'), 'there') == 'HELLO'
    assert strxor(strxor('hello', 'THERE'), 'hELLO') == 'There'