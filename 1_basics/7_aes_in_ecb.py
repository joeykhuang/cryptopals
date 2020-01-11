from Crypto.Cipher import AES
import base64


def aes_decode_with_key(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext).decode()
    return plaintext


def main():
    f = open('7.txt', 'r')
    raw_string = base64.b64decode(''.join(f.read().splitlines()))
    plaintext = aes_decode_with_key(raw_string, b'YELLOW SUBMARINE')
    plaintext = aes_decode_with_key(b'\xe51\xa4\xac^\x92Bx\t\xceH\xaaO\x8b\xec\xa1', b'YELLOW SUBMARINE')
    print(plaintext)


if __name__ == "__main__":
    main()
