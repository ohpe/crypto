#!/usr/bin/env python
# coding=utf-8

"""
Coursera Crypto I - Week 4 - Programming Project
CBC Padding Oracle attack against: crypto-class.appspot.com.

Giuseppe Trotta
"""

import urllib2
import re
import multiprocessing.pool
import threading

# Constants
TARGET = 'http://crypto-class.appspot.com/po?er='
CIPHERTEXT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
BSIZE = 32  # AES blocks

# Split in blocks
# C[0] is the Initialization Vector (IV)
blocks = len(CIPHERTEXT) / BSIZE
C = [None] * blocks
for i in range(blocks):
    C[i] = CIPHERTEXT[i * BSIZE: i * BSIZE + BSIZE]


def PaddingOracle(q):
    target = TARGET + urllib2.quote(q)  # Create query URL
    req = urllib2.Request(target)  # Send HTTP request to server
    try:
        f = urllib2.urlopen(req)  # Wait for response
    except urllib2.HTTPError, e:
        # print "We got: %d" % e.code       # Print response code
        if e.code == 404:
            return True  # good padding
        return False  # bad padding


def strxor(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))


def attack(b1, b2, charset=list(reversed(range(16))) + range(16, 256), size=16):
    # Init the message
    m = '00' * size

    # For AES the bytes are 16
    for i in range(1, (size + 1)):
        for j in charset:

            # Guessed byte
            byte = '{0:02x}'.format(int(j))

            # Set the guessed byte in position
            g = re.findall('.{1,2}', m)
            g[size - i] = byte
            g = ''.join(g)

            # Create the padding
            # ..01, ..0202, ..030303, ..04040404, ..
            pad = '00' * (16 - i) + '{0:02x}'.format(i) * i

            # Magic here
            modb1 = strxor(strxor(b1.decode('hex'), g.decode('hex')), pad.decode('hex')).encode('hex')
            ciphertext = modb1 + b2

            if PaddingOracle(ciphertext):
                m = g
                print m.decode('hex')
                break

    return m


"""
TODO ASCII Character Frequency Analysis
Improve the attack intelligence using a Character Frequency Charset
A possible example, form http://reusablesec.blogspot.it/2009/05/character-frequency-analysis-info.html
"""
letters = " aeorisn1tl2md0cp3hbuk45g9687yfwjvzxqASERBTMLNPOIDCHGKFJUW.!Y*@V-ZQX_$#,/+?;^%~=&`\)][:<(æ>\"ü|{'öä}"
# speed debug, build the charset from the solution
#letters = "The Magic Words are Squeamish Ossifrage"

# Attack the blocks in parallel
pool = multiprocessing.pool.ThreadPool(processes=blocks - 1)
M = [None] * (blocks - 1)
for i in range(len(M)):
    charset = re.findall('.{3}', ''.join('{:03}'.format(ord(c)) for c in set(letters)))
    if i == len(M) - 1:
        # The last charset must include the first non printable 16 chars, required for padding!
        charset = list(reversed(range(16))) + charset

    M[i] = pool.apply_async(attack, (C[i], C[i + 1], charset))

for i in range(len(M)):
    M[i] = M[i].get()

message = ""
for i in range(len(M)):
    message += M[i].decode('hex')

print "\n\n\033[92m"
print "[*] ", message
print "\033[0m"
