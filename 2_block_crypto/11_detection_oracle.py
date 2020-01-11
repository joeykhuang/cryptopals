import importlib
import random

cbc = importlib.import_module("2_block_crypto.10_cbc_mode")


def generate_random_bytes(length_of_bytes):
    return bytes(random.sample(range(256), length_of_bytes))


def encryption_oracle(plaintext):
    aes_key = generate_random_bytes(16)
    plaintext_length = len(plaintext)
    pad_length = 16 - (plaintext_length % 16)
    before_pad = generate_random_bytes(random.randint(5, 10))
    after_pad_length = 16 + (pad_length - len(before_pad)) if (pad_length - len(before_pad)) < 0 else (pad_length - len(before_pad))
    after_pad = generate_random_bytes(after_pad_length)
    plaintext = before_pad + plaintext + after_pad
    ecb_or_cbc = random.randint(0, 1)
    if ecb_or_cbc:
        random_iv = generate_random_bytes(16)
        return [cbc.cbc_encode_with_key(plaintext, aes_key, 16, random_iv), "CBC"]
    else:
        return [cbc.ecb_encode_with_key(plaintext, aes_key), "ECB"]


def detect_encryption_oracle(ciphertext):
    broken_chunks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    num_reps = len(broken_chunks) - len(set(broken_chunks))
    return "CBC" if num_reps == 0 else "ECB"


def main():
    for i in range(30, 50):
        correct_count = 0
        for j in range(1000):
            [encrypted_text, real_encryption_method] = encryption_oracle(b'A' * i)
            encrypted_method = detect_encryption_oracle(encrypted_text)
            if real_encryption_method == encrypted_method:
                correct_count += 1
        print(i, correct_count/1000)


if __name__ == '__main__':
    main()
