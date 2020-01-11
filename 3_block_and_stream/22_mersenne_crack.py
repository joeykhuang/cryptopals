import importlib
import random
import time

mt19937 = importlib.import_module('3_block_and_stream.21_mersenne_twister')


def generate_random_mersenne():
    wait_rand_secs = random.randint(60, 1000)
    time.sleep(wait_rand_secs)
    current_time = int(time.time())
    wait_rand_secs = random.randint(60, 1000)
    time.sleep(wait_rand_secs)
    return mt19937.random(current_time, 1)


def mersenne_oracle(random_mersenne_output):
    current_time = int(time.time())
    for i in range(current_time - 2000, current_time):
        if mt19937.random(i, 1) == random_mersenne_output:
            return i


def main():
    print(mersenne_oracle(generate_random_mersenne()))


if __name__ == '__main__':
    main()
