import hashlib
import random


def diffie_hellman_auto_private_key(p, g):
    a = random.randint(0, p) % p
    A = pow(g, a, p)

    b = random.randint(0, p) % p
    B = pow(g, b, p)

    s = pow(B, a, p)
    m = hashlib.md5()
    m.update(str(s).encode())
    return m.digest()


def diffie_hellman(p, private, public):
    s = pow(public, private, p)
    m = hashlib.md5()
    m.update(str(s).encode())
    return m.digest()


def main():
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024", 16)
    g = 1
    print(diffie_hellman_auto_private_key(p, g))
    print(diffie_hellman(p, 1, 1))
    print(diffie_hellman(p, 2, 1))
    return None


if __name__ == '__main__':
    main()
