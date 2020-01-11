import importlib

pad = importlib.import_module("2_block_crypto.9_pkcs7")


class PaddingError(Exception):
    pass


def validate_pkcs(ciphertext, block_size):
    if len(ciphertext) % block_size != 0:
        raise PaddingError

    pad_size = int(ciphertext[-1])
    if ciphertext[-pad_size:] != bytes([pad_size]) * pad_size:
        raise PaddingError

    return ciphertext[:-pad_size]


def main():
    assert validate_pkcs(b'ICE ICE BABY\x04\x04\x04\x04', 16) == b'ICE ICE BABY'

    print(validate_pkcs(b'ICE ICE BABY\x04\x04\x04\x04', 16))

    try:
        print(validate_pkcs(b'ICE ICE BABY\x05\x05\x05\x05', 16))
        print(validate_pkcs(b'ICE ICE BABY\x01\x02\x03\x04', 16))
    except PaddingError:
        print("Padding Error")


if __name__ == '__main__':
    main()
