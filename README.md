Cryptography
============

Numerous cryptography functions i've used to solve problems.

Some files require the [PyCrypto](https://www.dlitz.net/software/pycrypto/) package to be installed in order to run.

* crypto_functions.py : utility functions such as the ability to xor ascii strings and encrypt strings as hex encoded integers.
* crypto_tests.py: a number of tests used to ensure crypto_functions.py still follows the expected behaviour
* aes_tool.py: Tool for encrypting and decrypting text using the AES block cipher.
* crypto_task.py: utility script that performs a many time key attack on OTP using crib dragging techniques.
