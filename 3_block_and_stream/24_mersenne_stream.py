import importlib
import random

mt = getattr(importlib.import_module("3_block_and_stream.21_mersenne_twister"), "mt_19937")
aes = importlib.import_module("2_block_crypto.10_cbc_mode")

random_seed = random.randint(10000, 65536)


def mt_cipher(text, seed):
    crypto_mt_stream = mt(seed=seed)
    keystream = ''.join(str(x) for x in crypto_mt_stream.random(len(text) // 8))[:len(text)]
    return aes.xor_with_key(text, keystream)


def decrypt_mt_cipher(ciphertext):
    for i in range(10000, 65536):
        if mt_cipher(ciphertext, i)[-14:] == (b'A' * 14):
            return i


def main():
    print(random_seed)
    ciphertext = mt_cipher("A" * 350, random_seed)
    print(decrypt_mt_cipher(ciphertext))


if __name__ == '__main__':
    main()
