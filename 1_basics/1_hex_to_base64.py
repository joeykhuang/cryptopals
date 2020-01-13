import binascii

import pybase64

hexbytes = binascii.unhexlify(input())

print(pybase64.b64encode(hexbytes))
