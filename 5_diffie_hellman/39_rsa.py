import math
import random


def fermat_primality_test(p, s=5):
    if p == 2:
        return True
    if not p & 1:  # if p is even, number cant be a prime
        return False

    for i in range(s):
        a = random.randrange(2, p - 2)
        x = pow(a, p - 1, p)  # a**(p-1) % p
        if x != 1:
            return False
    return True


def square_and_multiply(x, k, p=None):
    b = bin(k).lstrip('0b')
    r = 1
    for i in b:
        r = r ** 2
        if i == '1':
            r = r * x
        if p:
            r %= p
    return r


def miller_rabin_primality_test(p, s=5):
    if p == 2:  # 2 is the only prime that is even
        return True
    if not (p & 1):  # n is a even number and can't be prime
        return False

    p1 = p - 1
    u = 0
    r = p1  # p-1 = 2**u * r

    while r % 2 == 0:
        r >>= 1
        u += 1

    assert p - 1 == 2 ** u * r

    def witness(a):
        z = square_and_multiply(a, r, p)
        if z == 1:
            return False

        for i in range(u):
            z = square_and_multiply(a, 2 ** i * r, p)
            if z == p1:
                return False
        return True

    for j in range(s):
        a = random.randrange(2, p - 2)
        if witness(a):
            return False

    return True


def generate_primes(n=512, k=1):
    assert k > 0
    assert n > 0 and n < 4096

    necessary_steps = math.floor(math.log(2 ** n) / 2)
    x = random.getrandbits(n)

    primes = []

    while k > 0:
        if miller_rabin_primality_test(x, s=7):
            primes.append(x)
            k = k - 1
        x = x + 1

    return primes


def extended_gcd(a, b):
    if a < b:
        a, b = b, a
    s, old_s = (0, 1)
    t, old_t = (1, 0)
    r, old_r = (abs(b), abs(a))

    while r:
        old_r, (quotient, r) = r, divmod(old_r, r)
        s, old_s = old_s - quotient * s, s
        t, old_t = old_t - quotient * t, t

    return old_r, old_s * (-1 if a < 0 else 1), old_t * (-1 if b < 0 else 1)


def invmod(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return y % m


class RSA_Keygen:

    def __init__(self):
        self.p, self.q = generate_primes(k=2)
        self.n = self.p * self.q
        self.et = (self.p - 1) * (self.q - 1)
        self.e = 3
        while extended_gcd(self.e, self.et)[0] != 1:
            self.p, self.q = generate_primes(k=2)
            self.n = self.p * self.q
            self.et = (self.p - 1) * (self.q - 1)
        self.d = invmod(self.e, self.et)

    def get_public_key(self):
        return [self.e, self.n]

    def get_private_key(self):
        return [self.d, self.n]


def rsa_encrypt(message, public_key):
    e, n = public_key
    return pow(message, e, n)


def rsa_decrypt(message, private_key):
    d, n = private_key
    return pow(message, d, n)


def main():
    RSA = RSA_Keygen()
    public_key = RSA.get_public_key()
    private_key = RSA.get_private_key()
    a = rsa_encrypt(42, public_key)
    print(a)
    print(rsa_decrypt(a, private_key))


if __name__ == '__main__':
    main()
