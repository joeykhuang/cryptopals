import importlib

mt = getattr(importlib.import_module("3_block_and_stream.21_mersenne_twister"), "mt_19937")


def int_to_bit(integer):
    return [int(x) for x in '{:032b}'.format(integer)]


def bit_to_int(bit_list):
    return int("".join(str(x) for x in bit_list), base=2)


def inv_xor_mask(value, shift_distance, mask, shift_dir):
    # shift_dir: 0 == left; 1 == right
    value_bit = int_to_bit(value)
    mask_bit = int_to_bit(mask)
    if shift_dir == 0:
        mask_bit.reverse()
        value_bit.reverse()

    x = [0] * 32
    for n in range(32):
        if n < shift_distance:
            x[n] = value_bit[n]
        else:
            x[n] = value_bit[n] ^ (mask_bit[n] & x[n - shift_distance])

    if shift_dir == 0:
        x.reverse()

    return bit_to_int(x)


def untemper(mt_output):
    reconstructed_state = mt_output
    reconstructed_state = inv_xor_mask(reconstructed_state, mt.l_mersenne, 0xFFFFFFFF, 1)
    reconstructed_state = inv_xor_mask(reconstructed_state, mt.t_bit_shift, mt.c_bit_mask, 0)
    reconstructed_state = inv_xor_mask(reconstructed_state, mt.s_bit_shift, mt.b_bit_mask, 0)
    reconstructed_state = inv_xor_mask(reconstructed_state, mt.u_mersenne, mt.d_mersenne, 1)
    return reconstructed_state


def clone_mt(mt_to_clone: mt):
    mt_output_list = mt_to_clone.random(624)
    state = [untemper(x) for x in mt_output_list]
    return mt(state=state)


def clone_mt_from_output(mt_output_list):
    state = [untemper(x) for x in mt_output_list]
    return mt(state=state)


def main():
    PRNG = mt()
    cloned_PRNG = clone_mt(PRNG)
    print(PRNG.random(20))
    print(cloned_PRNG.random(20))
    return None


if __name__ == '__main__':
    main()
