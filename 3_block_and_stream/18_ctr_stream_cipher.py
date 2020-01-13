import base64
import importlib

from Crypto.Cipher import AES

aes = importlib.import_module("2_block_crypto.10_cbc_mode")


def little_endian(number, num_bits):
    return bytearray.fromhex(hex(number)[2:].zfill(num_bits // 4))[::-1]


def ctr_mode(text, key, nonce=(b'\x00' * 8)):
    text_blocks = [text[i:i + 16] for i in range(0, len(text), 16)]
    altered_text = b''
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)
    for i in range(len(text_blocks)):
        counter = nonce + little_endian(i, 64)
        encrypted_key = cr.encrypt(counter)
        block_plaintext = aes.xor_with_key(text_blocks[i], encrypted_key[:len(text_blocks[i])])
        altered_text += block_plaintext
    return altered_text


def main():
    b64_decrypted_ciphertext = base64.b64decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    print(ctr_mode(b64_decrypted_ciphertext, b'YELLOW SUBMARINE', b'\x00' * 8))


if __name__ == '__main__':
    main()
