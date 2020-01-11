import importlib
import random

cbc = importlib.import_module("2_block_crypto.10_cbc_mode")

pad = importlib.import_module("2_block_crypto.9_pkcs7")


def generate_random_bytes(length_of_bytes):
    return bytes(random.sample(range(256), length_of_bytes))


aes_key = generate_random_bytes(16)

random_iv = generate_random_bytes(16)


def encode_string(raw_string):
    global aes_key, random_iv
    prepend = "comment1=cooking%20MCs;userdata=".encode()
    append = ";comment2=%20like%20a%20pound%20of%20bacon".encode()
    raw_string = prepend + raw_string.replace(";", "?").replace("=", "?").encode() + append
    ciphertext = cbc.cbc_encode_with_key(pad.pkcs(raw_string, 16), aes_key, 16, random_iv)
    return ciphertext


def decode_and_check_admin(ciphertext):
    plaintext = cbc_decode_with_key(ciphertext, aes_key, 16, random_iv)
    cookie_dict = dict(map(lambda s: s.split(b'\x3d'), plaintext.split(b'\x3b')))
    if b'admin' in cookie_dict.keys() and cookie_dict[b'admin'] == b'true':
        return True
    else:
        return False


def cbc_decode_with_key(ciphertext, key, block_size, iv):
    ciphertext_blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext_blocks = []
    final = b''
    last_decrypted_block = cbc.ecb_decode_with_key(ciphertext_blocks[-1], key)
    for each_block in ciphertext_blocks[::-1][1:]:
        xor_result = cbc.xor_with_key(each_block, last_decrypted_block)
        last_decrypted_block = cbc.ecb_decode_with_key(each_block, key)
        plaintext_blocks.append(xor_result)
    plaintext_blocks.append(cbc.xor_with_key(cbc.ecb_decode_with_key(ciphertext_blocks[0], key), iv))
    for each_plaintext_block in plaintext_blocks[::-1]:
        final += each_plaintext_block
    return final


def cbc_bit_flip():
    attack_string = encode_string(";admin=true")
    ciphertext = list(attack_string)
    ciphertext[16] = ciphertext[16] ^ ord("?") ^ ord(";")
    ciphertext[22] = ciphertext[22] ^ ord("?") ^ ord("=")
    return decode_and_check_admin(bytes(ciphertext))


def main():
    print(cbc_bit_flip())


if __name__ == '__main__':
    main()
