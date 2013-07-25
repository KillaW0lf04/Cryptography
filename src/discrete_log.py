import time

import gmpy2
from gmpy2 import mpz

p = mpz('13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171')
g = mpz('11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568')
h = mpz('3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333')

#print '!!!!!!!!!!%s' % gmpy2.divm(h, g, p)

hash_list_eq1 = {}

B = mpz(2**20)
gB = gmpy2.powmod(g, B, p)

print 'Building Hash Table'
t0 = time.time()

# Equation h/g**x1
for x1 in xrange(1, 2**20):
    temp = gmpy2.powmod(g, x1, p)
    temp = gmpy2.div(h, temp)
    print temp

    temp = gmpy2.c_mod(temp, p)
    hash_list_eq1[temp] = x1

print 'Finished building hash table (%s)' % (time.time() - t0)

print 'Comparing results to hash table'
t0 = time.time()

# Equation (g**B)**x0
for x0 in xrange(1, 2**20):
    value = gmpy2.powmod(gB, x0, p)

    if value in hash_list_eq1:
        print 'FOUND! %s, %s' % (x0, hash_list_eq1[value])
        print 'RESULT = %s' % (gmpy2.c_mod(gmpy2.add(gmpy2.mul(x0, B), x1), p))

print 'Finished algorithm (%s)' % (time.time() - t0)