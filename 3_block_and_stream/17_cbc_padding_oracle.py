import importlib
import random

pad = importlib.import_module("2_block_crypto.9_pkcs7")
aes = importlib.import_module("2_block_crypto.11_detection_oracle")
valid = importlib.import_module("2_block_crypto.15_pkcs_validation")
bit_flipping = importlib.import_module("2_block_crypto.16_cbc_bitflipping")

BLOCK_SIZE = 16
aes_key = aes.generate_random_bytes(BLOCK_SIZE)
random_iv = aes.generate_random_bytes(BLOCK_SIZE)


def encrypt_padding_oracle():
    global aes_key
    global random_iv
    random_string_list = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                          "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                          "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                          "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                          "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                          "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                          "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                          "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                          "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                          "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
    random_string = pad.pkcs(random.choice(random_string_list), BLOCK_SIZE)
    ciphertext = aes.cbc.cbc_encode_with_key(random_string, aes_key, BLOCK_SIZE, random_iv)
    return [ciphertext, random_iv]


def is_padding_ok(ciphertext):
    decrypted_text = bit_flipping.cbc_decode_with_key(ciphertext, aes_key, BLOCK_SIZE, random_iv)
    try:
        valid.validate_pkcs(decrypted_text, BLOCK_SIZE)
    except valid.PaddingError:
        return False
    else:
        return True


def padding_oracle_attack(ciphertext):
    guessed_clear = b''
    ciphertext = random_iv + ciphertext
    blocks = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    for each_block in range(len(blocks) - 1, 0, -1):
        spliced_ciphertext = blocks[each_block - 1] + blocks[each_block]
        decoded_bytes = b'?' * BLOCK_SIZE

        for byte in range(BLOCK_SIZE - 1, -1, -1):
            new_pad_len = BLOCK_SIZE - byte

            hacked_ciphertext_tail = b''
            for pad_index in range(1, new_pad_len):
                hacked_ciphertext_tail += bytearray.fromhex(
                    '{:02x}'.format(new_pad_len ^ decoded_bytes[byte + pad_index]))

            for i in range(0, 256):
                attack_str = bytearray.fromhex('{:02x}'.format((i ^ spliced_ciphertext[byte])))
                hacked_ciphertext = spliced_ciphertext[
                                    :byte] + attack_str + hacked_ciphertext_tail + spliced_ciphertext[
                                                                                   byte + 1 + new_pad_len - 1:]

                if is_padding_ok(hacked_ciphertext):

                    test_correctness = hacked_ciphertext[:byte - 1] + bytearray.fromhex(
                        '{:02x}'.format((1 ^ hacked_ciphertext[byte]))) + hacked_ciphertext[byte:]
                    if not is_padding_ok(test_correctness):
                        continue

                    decoded_bytes = decoded_bytes[:byte] + bytearray.fromhex(
                        '{:02x}'.format(hacked_ciphertext[byte] ^ new_pad_len)) + decoded_bytes[byte + 1:]
                    guessed_clear = bytearray.fromhex('{:02x}'.format(i ^ new_pad_len)) + guessed_clear
                    break
    return guessed_clear[:-guessed_clear[-1]]


def decrypt_padding_oracle():
    encrypted_random_strings = []
    decrypted_strings = []
    while len(encrypted_random_strings) < 10:
        new_encrypted_string = encrypt_padding_oracle()[0]
        if new_encrypted_string not in encrypted_random_strings:
            encrypted_random_strings.append(new_encrypted_string)
    for each_random_string in encrypted_random_strings:
        decrypted_strings.append(padding_oracle_attack(each_random_string).decode())
    return decrypted_strings


def cbc_padding_oracle():
    return decrypt_padding_oracle()


def main():
    print('\n'.join(cbc_padding_oracle()))


if __name__ == '__main__':
    main()
