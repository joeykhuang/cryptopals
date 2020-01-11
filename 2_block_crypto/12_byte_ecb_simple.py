import base64
import importlib

oracle = importlib.import_module("11_detection_oracle")
pad = importlib.import_module("9_pkcs7")

aes_key = oracle.generate_random_bytes(16)


def encryption_oracle(plaintext, block_size=16):
    global aes_key
    after_encrypted_text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK "
    after_pad = base64.b64decode(after_encrypted_text)
    byte_text = bytes(plaintext) + after_pad
    encrypted_text = oracle.cbc.ecb_encode_with_key(pad.pkcs(byte_text, block_size), aes_key)
    broken_chunks = [encrypted_text[i:i + block_size] for i in range(0, len(encrypted_text), block_size)]
    num_reps = len(broken_chunks) - len(set(broken_chunks))
    return [encrypted_text, num_reps]


def find_block_size():
    for i in range(1, 500):
        encryption_test = encryption_oracle(b'A' * i)
        if encryption_test[1] >= 1:
            return i // 2


def decrypt_ecb():
    unknown_string_size = 144
    As = b'A' * unknown_string_size
    guessed = b''

    start = (len(As) // 16 - 1) * 16
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
