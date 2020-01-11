def get_best_string(hex_strings):
    potential_messages = []
    for hex_string in hex_strings:
        ciphertext = bytes.fromhex(hex_string)
        broken_chunks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
        num_reps = len(broken_chunks) - len(set(broken_chunks))
        potential_messages.append({'ciphertext': ciphertext, 'reps': num_reps})
    best_score = sorted(potential_messages, key=lambda x: x['reps'], reverse=True)[0]['ciphertext']
    return best_score


def main():
    f = open('8.txt', 'r')
    hex_strings = f.read().splitlines()
    print(get_best_string(hex_strings))


if __name__ == '__main__':
    main()
