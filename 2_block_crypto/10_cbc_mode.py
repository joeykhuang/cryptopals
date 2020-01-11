from Crypto.Cipher import AES
import base64


def xor_with_key(input_string, key):
    if type(input_string) != bytes:
        input_string = input_string.encode()
    if type(key) != bytes:
        key = key.encode()
    output_bytes = b''
    for i in range(len(input_string)):
        output_bytes += bytes([input_string[i] ^ key[i]])
    return output_bytes


def ecb_encode_with_key(plaintext, key):
    aes = AES.new(key, AES.MODE_ECB)
    ciphertext = aes.encrypt(plaintext)
    return ciphertext


def ecb_decode_with_key(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext)
    return plaintext


def cbc_encode_with_key(plaintext, key, block_size, iv):
    text_blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    final_string = b''
    encrypted_text = iv
    for each_text_block in text_blocks:
        encoded_block = ecb_encode_with_key(xor_with_key(each_text_block, encrypted_text), key)
        final_string += encoded_block
        encrypted_text = encoded_block
    return final_string


def cbc_decode_with_key(ciphertext, key, block_size, iv):
    ciphertext_blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext_blocks = []
    final_string = ""
    last_decrypted_block = ecb_decode_with_key(ciphertext_blocks[-1], key)
    for each_block in ciphertext_blocks[::-1][1:]:
        xor_result = xor_with_key(each_block, last_decrypted_block)
        last_decrypted_block = ecb_decode_with_key(each_block, key)
        plaintext_blocks.append(xor_result)
    plaintext_blocks.append(xor_with_key(ecb_decode_with_key(ciphertext_blocks[0], key), iv))
    for each_plaintext_block in plaintext_blocks[::-1]:
        final_string += each_plaintext_block.decode()
    return final_string


def main():
    with open('10.txt', 'rb') as f:
        ciphertext = base64.b64decode(f.read())
    decrypted_string = cbc_decode_with_key(ciphertext, b'YELLOW SUBMARINE', 16, b'\x00' * 16)
    # encoded_string = cbc_encode_with_key(decrypted_string.encode(), b'YELLOW SUBMARINE', 16, b'\x00'*16)
    print(decrypted_string)


if __name__ == "__main__":
    main()
