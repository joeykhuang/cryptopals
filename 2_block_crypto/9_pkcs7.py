def pkcs(ciphertext, block_size):
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    pad_size = block_size - (len(ciphertext) % block_size)
    ciphertext += bytes([pad_size]) * pad_size
    return ciphertext


def main():
    print(pkcs(b'YELLOW SUBMARINE', 16))


if __name__ == "__main__":
    main()
