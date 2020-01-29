import binascii
import importlib
import struct

sha1 = importlib.import_module("4_stream_and_randomness.28_sha1_mac")
oracle = importlib.import_module("2_block_crypto.11_detection_oracle")

key = b'jklafuidxijaf'

lrot = lambda x, n: (x << n) | (x >> (32 - n))


def calculate_padding(length):
    padding = b'\x80'
    padding += bytes((56 - length % 64) % 64)
    padding += struct.pack('<Q', length * 8)
    return padding


class MD4():
    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self, message, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476, prefix_length=None):
        self.A, self.B, self.C, self.D = (A, B, C, D)
        if prefix_length is None:
            length = struct.pack('<Q', len(message) * 8)
        else:
            length = struct.pack('<Q', prefix_length * 8)
        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]
        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length
        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        X = list(struct.unpack('<' + 'I' * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = lrot((A + self._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = lrot((D + self._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = lrot((C + self._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = lrot((B + self._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = lrot((A + self._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = lrot((D + self._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = lrot((C + self._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = lrot((B + self._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = lrot((A + self._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = lrot((D + self._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = lrot((C + self._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = lrot((B + self._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return struct.pack('<IIII', self.A, self.B, self.C, self.D)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode()


def md4_auth(md4_object):
    return md4_object.hexdigest()


def main():
    original = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    MD4hasher = MD4(b'a')
    sha1hash = md4_auth(MD4hasher)
    a = int(sha1hash[0:8], 16)
    b = int(sha1hash[8:16], 16)
    c = int(sha1hash[16:24], 16)
    d = int(sha1hash[24:32], 16)
    #
    for sec_len in range(0, 1):
        padding = calculate_padding(len(original) + sec_len)
        print(padding)
        newmessage = original + padding + b';admin=true'
        hsh = MD4(b';admin=true', a, b, c, d, prefix_length=len(original) + len(padding) + sec_len)
        if md4_auth(MD4(newmessage)) == md4_auth(hsh):
            print(newmessage)
            print("success")
            break


if __name__ == '__main__':
    main()
