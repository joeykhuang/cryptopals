import base64
import importlib
import random

easy_byte = importlib.import_module("12_byte_ecb_simple")

aes_key = easy_byte.oracle.generate_random_bytes(16)

random_prefix_length = random.randint(1, 16)
random_prefix = easy_byte.oracle.generate_random_bytes(random_prefix_length)


def encryption_oracle(plaintext, block_size=16):
    global aes_key
    global random_prefix
    after_encrypted_text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK "
    after_pad = base64.b64decode(after_encrypted_text)
    byte_text = random_prefix + bytes(plaintext) + after_pad
    encrypted_text = easy_byte.oracle.cbc.ecb_encode_with_key(easy_byte.pad.pkcs(byte_text, block_size),
                                                              aes_key)
    broken_chunks = [encrypted_text[i:i + block_size] for i in range(0, len(encrypted_text), block_size)]
    num_reps = len(broken_chunks) - len(set(broken_chunks))
    return [encrypted_text, num_reps]


def find_prefix_length():
    for i in range(16, 48):
        encryption_test = encryption_oracle(b'A' * i)
        if encryption_test[1] >= 1:
            return 48 - i


def decrypt_ecb():
    prefix_length = find_prefix_length()
    unknown_string_size = 144
    As = b'A' * (16 - prefix_length + unknown_string_size)
    guessed = b''

    start = (len(As) // 16) * 16
    stop = start + 16

    while len(As) > 0:
        As = As[:-1]
        new_encrypted = encryption_oracle(As)
        new_encrypted_text = new_encrypted[0][start:stop]

        found_next_byte = False
        for j in range(0, 256):
            byte_decrypt_list = As + guessed + bytes([j])
            new_encrypted = encryption_oracle(byte_decrypt_list)[0][start:stop]
            if new_encrypted == new_encrypted_text:
                guessed += bytes([j])
                found_next_byte = True
                break

        if not found_next_byte:
            guessed = guessed[:-1]
            guessed += bytes([(unknown_string_size - len(guessed))]) * (unknown_string_size - len(guessed))
            break

    return guessed.strip(b'\x04')


def main():
    print(decrypt_ecb().decode())


if __name__ == '__main__':
    main()
