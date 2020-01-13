import base64
import importlib

ctr = importlib.import_module("3_block_and_stream.18_ctr_stream_cipher")
aes = importlib.import_module("1_basics.7_aes_in_ecb")
oracle = importlib.import_module("2_block_crypto.11_detection_oracle")

random_key = oracle.generate_random_bytes(16)


def edit(ciphertext, key, offset, new_text):
    plaintext = ctr.ctr_mode(ciphertext, key)
    new_plaintext = plaintext[:offset] + new_text
    return ctr.ctr_mode(new_plaintext, key)


def find_key_stream(encrypted_text):
    all_As = b'\x41' * len(encrypted_text)
    key_stream = oracle.cbc.xor_with_key(edit(encrypted_text, random_key, 0, all_As), all_As)
    return key_stream


def find_plain_text_ctr(encrypted_text):
    key_stream = find_key_stream(encrypted_text)
    found_plaintext = oracle.cbc.xor_with_key(encrypted_text, key_stream)
    return found_plaintext.decode()


def main():
    with open("25.txt", "r") as file:
        a = base64.b64decode(''.join(file.read().splitlines()))
    plaintext = aes.aes_decode_with_key(a, b'YELLOW SUBMARINE')
    ctr_encrypted_text = ctr.ctr_mode(plaintext, random_key)
    print(find_plain_text_ctr(ctr_encrypted_text))


if __name__ == '__main__':
    main()
