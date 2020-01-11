def xor_with_key(input_string, key):
    num_bytes = len(key)
    output_bytes = b''
    for i in range(len(input_string)):
        output_bytes += bytes([input_string[i] ^ key[i % num_bytes]])
    return output_bytes


def main():
    ciphertext = b"Burning 'em, if you ain't quick and nimble\n I go crazy when I hear a cymbal"
    cipherkey = b'ICE'
    print(xor_with_key(ciphertext, cipherkey).hex())


if __name__ == '__main__':
    main()
