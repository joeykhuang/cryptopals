import importlib
single_byte_xor = importlib.import_module("3_single_byte_xor")


def single_char_xor(input_bytes, char_value):
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes


def get_best_string(hex_strings):
    potential_messages = []
    for hex_string in hex_strings:
        ciphertext = bytes.fromhex(hex_string)
        for key_value in range(256):
            message = single_char_xor(ciphertext, key_value)
            score = single_byte_xor.get_english_score(message)
            data = {
                'message': message,
                'score': score,
                'key': key_value
            }
            potential_messages.append(data)
    best_score = sorted(potential_messages, key=lambda x: x['score'], reverse=True)[0]['message']
    return best_score


def main():
    f = open('4.txt', 'r');
    hex_strings = f.read().splitlines()
    print(get_best_string(hex_strings))


if __name__ == '__main__':
    main()
