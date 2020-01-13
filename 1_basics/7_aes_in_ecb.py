import base64

from Crypto.Cipher import AES


def aes_decode_with_key(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext).decode()
    return plaintext


def main():
    f = open('7.txt', 'r')
    raw_string = base64.b64decode(''.join(f.read().splitlines()))
    plaintext = aes_decode_with_key(raw_string, b'YELLOW SUBMARINE')
    print(plaintext)


if __name__ == "__main__":
    main()
