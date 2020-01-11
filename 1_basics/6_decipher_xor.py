import base64
import importlib

xor = importlib.import_module("4_detect_xor")


def turn_string_to_bits(string):
    bit_arrays = ""
    for char in string:
        bit_arrays += bin(char)[2:].zfill(8)
    return [int(a) for a in bit_arrays]


def find_hamming_distance(first_string, second_string):
    first_string_bits = turn_string_to_bits(first_string)
    second_string_bits = turn_string_to_bits(second_string)
    diff_array = [abs(a - b) for a, b in zip(first_string_bits, second_string_bits)]
    return sum(diff_array)


def guess_key_size(raw_string):
    average_distances = {}
    for key_size in range(2, 41):
        distances = []
        chunks = [raw_string[i:i + key_size] for i in range(0, len(raw_string), key_size)]
        while True:
            try:
                chunk_1 = chunks[0]
                chunk_2 = chunks[1]
                distance_between = find_hamming_distance(chunk_1, chunk_2)
                distances.append(distance_between / float(key_size))

                del chunks[0]
                del chunks[1]
            except Exception as e:
                break
        average_distances[key_size] = sum(distances) / float(len(distances))
    return sorted(average_distances.items(), key=lambda kv: (kv[1], kv[0]))[:3]


def divide_text(raw_string, key_size):
    broken_text = [raw_string[i:i + key_size] for i in range(0, len(raw_string), key_size)]
    text_blocks = []
    for i in range(0, key_size):
        text_blocks.append([broken_text[j][i] for j in range(0, len(broken_text) - 1)])
    tracker = 0
    for char in broken_text[-1]:
        text_blocks[tracker].append(char)
        tracker += 1
    return text_blocks


def find_key_for_each_block(ciphertext):
    potential_messages = []
    for key_value in range(256):
        message = xor.single_char_xor(ciphertext, key_value)
        score = xor.get_english_score(message)
        data = {
            'message': message,
            'score': score,
            'key': key_value
        }
        potential_messages.append(data)
    best_score = sorted(potential_messages, key=lambda x: x['score'], reverse=True)[0]
    return [best_score['message'], best_score['key']]


def solve_xor(text_blocks):
    key = []
    messages = []
    for each_block_of_text in text_blocks:
        ciphertext = bytes(each_block_of_text)
        key.append(find_key_for_each_block(ciphertext)[1])
        messages.append(find_key_for_each_block(ciphertext)[0])
    final_message = ""
    for i in range(len(messages[6])):
        for each_message in messages:
            final_message += each_message.decode()[i]
    return [final_message, bytes(key)]


def main():
    f = open('6.txt', 'r')
    raw_string = base64.b64decode(''.join(f.read().splitlines()))
    text_blocks = divide_text(raw_string, guess_key_size(raw_string)[0][0])
    print(solve_xor(text_blocks)[0])


if __name__ == "__main__":
    main()
