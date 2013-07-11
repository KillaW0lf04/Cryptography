# Task to find a collision for two functions
# f1(x,y) = AES(y, x) xor y
# f2(x,y) = AES(x, x) xor x

from Crypto.Cipher import AES
from crypto_functions import strxor, hex_to_ascii

# ====================== QUESTION 8 ======================== #

y1 = hex_to_ascii(0x22222222222222222222222222222222)    # Some random value for y1
x1 = hex_to_ascii(0x11111111111111111111111111111111)    # Some random value for x1

cipher = AES.new(y1)

z = cipher.encrypt(x1)
z = strxor(z, y1)

y2 = hex_to_ascii(0x33333333333333333333333333333333)

cipher = AES.new(y2)

x2 = cipher.decrypt(strxor(z, y2))

print 'RESULTS'
print '*' * 20
print x1.encode('hex')
print y1.encode('hex')
print x2.encode('hex')
print y2.encode('hex')

# RESULTS #
# x1 = 11111111111111111111111111111111
# y1 = 22222222222222222222222222222222
# x2 = 0f41e44eb96c567bf2bd183f4dea95bf
# y2 = 33333333333333333333333333333333

# ====================== QUESTION 9 ======================== #

x3 = hex_to_ascii(0x11111111111111111111111111111111)    # Some random value for x3
y3 = hex_to_ascii(0x22222222222222222222222222222222)    # Some random value for y3

cipher = AES.new(x3)

z = strxor(cipher.encrypt(x3), y3)

x4 = hex_to_ascii(0x33333333333333333333333333333333)

cipher = AES.new(x4)

y4 = strxor(z, cipher.encrypt(x4))

print 'RESULTS'
print '*' * 20
print x3.encode('hex')
print y3.encode('hex')
print x4.encode('hex')
print y4.encode('hex')

# REUSLTS #
# x3 = 11111111111111111111111111111111
# y3 = 22222222222222222222222222222222
# x4 = 33333333333333333333333333333333
# y4 = c6cb17256563442e240b9380c416f85a


