import binascii
import importlib

import gmpy as gmpy

rsa = importlib.import_module("5_diffie_hellman.39_rsa")


def capture_pub_keys():
    RSA1 = rsa.RSA_Keygen()
    RSA2 = rsa.RSA_Keygen()
    RSA3 = rsa.RSA_Keygen()

    pub_1 = RSA1.get_public_key()
    pub_2 = RSA2.get_public_key()
    pub_3 = RSA3.get_public_key()

    return [pub_1, pub_2, pub_3]


def encrypt_plaintext_using_pub_keys(plaintext, pub_keys):
    plaintext = int(binascii.hexlify(plaintext.encode()), 16)

    ciphertext_1 = rsa.rsa_encrypt(plaintext, pub_keys[0])
    print(ciphertext_1, pub_keys[0])
    ciphertext_2 = rsa.rsa_encrypt(plaintext, pub_keys[1])
    print(ciphertext_2, pub_keys[1])
    ciphertext_3 = rsa.rsa_encrypt(plaintext, pub_keys[2])
    print(ciphertext_2, pub_keys[2])

    return [ciphertext_1, ciphertext_2, ciphertext_3]


def find_plaintext(ciphertext, public_keys):
    N1 = public_keys[0][1]
    N2 = public_keys[1][1]
    N3 = public_keys[2][1]

    m_s_1 = N2 * N3
    y1 = ciphertext[0] * m_s_1 * rsa.invmod(N1, m_s_1)

    m_s_2 = N1 * N3
    y2 = ciphertext[1] * m_s_2 * rsa.invmod(N2, m_s_2)

    m_s_3 = N2 * N1
    y3 = ciphertext[2] * m_s_3 * rsa.invmod(N3, m_s_3)

    mod_prod = N1 * N2 * N3

    result = (y1 + y2 + y3) % mod_prod
    cube_root = gmpy.mpz(result).root(3)[0].digits()
    print(cube_root)
    return binascii.unhexlify(str(hex(int(cube_root))[2:]))


def main():
    pub_keys = capture_pub_keys()
    ciphertexts = encrypt_plaintext_using_pub_keys("hello" * 100, pub_keys)
    print(find_plaintext(ciphertexts, pub_keys))


if __name__ == '__main__':
    main()
