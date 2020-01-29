import importlib
import random

ctr = importlib.import_module("3_block_and_stream.18_ctr_stream_cipher")


def generate_random_bytes(length_of_bytes):
    return bytes(random.sample(range(256), length_of_bytes))


ctr_key = generate_random_bytes(16)

random_nonce = generate_random_bytes(8)


def encode_string(raw_string):
    global random_nonce, ctr_key
    prepend = "comment1=cooking%20MCs;userdata=".encode()
    append = ";comment2=%20like%20a%20pound%20of%20bacon".encode()
    raw_string = prepend + raw_string.replace(";", "?").replace("=", "?").encode() + append
    ciphertext = ctr.ctr_mode(raw_string, ctr_key, nonce=random_nonce)
    return ciphertext


def decode_and_check_admin(ciphertext):
    plaintext = ctr.ctr_mode(ciphertext, ctr_key, nonce=random_nonce)
    print(plaintext)
    cookie_dict = dict(map(lambda s: s.split(b'\x3d'), plaintext.split(b'\x3b')))
    if b'admin' in cookie_dict.keys() and cookie_dict[b'admin'] == b'true':
        return True
    else:
        return False


def ctr_bit_flip():
    attack_string = encode_string(";admin=true")
    ciphertext = list(attack_string)
    ciphertext[32] = ciphertext[32] ^ ord("?") ^ ord(";")
    ciphertext[38] = ciphertext[38] ^ ord("?") ^ ord("=")
    return decode_and_check_admin(bytes(ciphertext))


def main():
    print(ctr_bit_flip())


if __name__ == '__main__':
    main()
