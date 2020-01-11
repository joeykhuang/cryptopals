import pybase64
import binascii

hexbytes = binascii.unhexlify(input())

print(pybase64.b64encode(hexbytes))
