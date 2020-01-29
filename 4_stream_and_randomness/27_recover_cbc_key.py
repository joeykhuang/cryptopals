import importlib

cbc = importlib.import_module("2_block_crypto.16_cbc_bitflipping")

key = cbc.generate_random_bytes(16)


def check_ascii_compliance(plaintext):
    return all(c < 128 for c in plaintext)


def decrypt_and_check_admin(ciphertext):
    global key
    plaintext = cbc.cbc_decode_with_key(ciphertext, key, 16, key)
    if not check_ascii_compliance(plaintext):
        raise Exception("The message is not valid", plaintext)

    return b';admin=true;' in plaintext


def get_key_from_insecure_cbc():
    block_length = 16

    p_1 = 'A' * block_length
    p_2 = 'B' * block_length
    p_3 = 'C' * block_length
    ciphertext = cbc.encode_string(p_1 + p_2 + p_3)

    forced_ciphertext = ciphertext[:block_length] + b'\x00' * block_length + \
                        ciphertext[:block_length]

    try:
        decrypt_and_check_admin(forced_ciphertext)
    except Exception as e:
        forced_plaintext = e.args[1]
        return cbc.cbc.xor_with_key(forced_plaintext[:block_length], forced_plaintext[-block_length:])

    raise Exception("Was not able to hack the key")


def main():
    print(get_key_from_insecure_cbc())
    print(key)


if __name__ == '__main__':
    main()
