import binascii
import os
from bitstring import BitArray

preSharedKey = os.urandom(64)
preSharedKeyHex = binascii.b2a_hex(preSharedKey)
print "PreSharedKey(hex) : " + preSharedKeyHex + "\n"
preSharedKeyInt = int(preSharedKeyHex,16)

nonce1 = os.urandom(64)
nonce1Hex = binascii.b2a_hex(nonce1)
print "Nonce1 : " + nonce1Hex + "\n"
nonce1Int = int(nonce1Hex,16)

nonce2 = os.urandom(64)
nonce2Hex = binascii.b2a_hex(nonce2)
nonce2Int = int(nonce2Hex,16)
print "Nonce2 : " + nonce2Hex + "\n"

key1 = preSharedKeyInt ^ nonce1Int
print "key1 : " + '%x' % key1 + "\n"
key2 = key1 ^ nonce2Int
print "key2 : " + '%x' % key2 + "\n"
