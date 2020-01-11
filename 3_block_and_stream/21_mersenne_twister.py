import random


class mt_19937:
    w_word_size = 32
    n_degree_recurrence = 624
    m_middle_word = 397
    r_sep_point = 31

    a_coefficients = 0x9908B0DF
    b_bit_mask, c_bit_mask = (0x9D2C5680, 0xEFC60000)
    t_bit_shift, s_bit_shift = (15, 7)
    u_mersenne, d_mersenne, l_mersenne = (11, 0xFFFFFFFF, 18)

    f = 1812433253

    index = n_degree_recurrence + 1
    lower_mask = 0xFFFFFFFF
    upper_mask = 0x00000000
    mt = []

    def __init__(self, seed=random.randint(1, 2147483647), state=None):
        if state is None:
            self.seed_mt(seed)
        else:
            self.mt = state
            self.index = self.n_degree_recurrence

    def seed_mt(self, seed):
        self.index = self.n_degree_recurrence
        self.mt = [seed]
        for i in range(1, self.n_degree_recurrence):
            temp_mt = self.f * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w_word_size - 2))) + i
            self.mt.append(temp_mt & 0xffffffff)

    def extract_number(self):
        if self.index >= self.n_degree_recurrence:
            if self.index > self.n_degree_recurrence:
                return "Generator never seeded"
            self.twist()
            self.index = 0

        y = self.mt[self.index]
        y ^= (y >> self.u_mersenne) & self.d_mersenne
        y ^= (y << self.s_bit_shift) & self.b_bit_mask
        y ^= (y << self.t_bit_shift) & self.c_bit_mask
        y ^= y >> self.l_mersenne

        self.index += 1
        return y & 0xffffffff

    def twist(self):
        for i in range(self.n_degree_recurrence):
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.n_degree_recurrence] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ self.a_coefficients
            self.mt[i] = self.mt[(i + self.m_middle_word) % self.n_degree_recurrence] ^ xA

    def random(self, num_return):
        random_numbers = [self.extract_number() for _ in range(num_return)]
        return random_numbers if len(random_numbers) > 1 else random_numbers[0]


def main():
    PRNG = mt_19937(12345)
    print(PRNG.random(20))


if __name__ == '__main__':
    main()
