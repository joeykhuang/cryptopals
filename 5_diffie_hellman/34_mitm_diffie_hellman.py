import importlib
import random

df = importlib.import_module("5_diffie_hellman.33_diffie_hellman")
oracle = importlib.import_module("2_block_crypto.11_detection_oracle")


class A_class:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.a = random.randint(1, self.p)
        self.A = pow(g, self.a, p)

    def init_with_B(self, B):
        B.receive_init(self.p, self.g, self.A)

    def receive_init(self, B_pub_key):
        self.B = B_pub_key
        self.s = df.diffie_hellman(self.p, self.a, self.B)

    def send_message_to_B(self, B, message):
        m = oracle.cbc.cbc_encode_with_key(message, self.s[:16], 16,
                                           b'A' * 16) + oracle.generate_random_bytes(16)
        B.receive_message(m)

    def receive_message(self, message):
        self.message = message


class B_class:
    def __init__(self):
        pass

    def init_with_A(self, A):
        A.receive_init(self.B)

    def receive_init(self, p, g, A):
        self.p = p
        self.g = g
        self.b = random.randint(1, self.p)
        self.B = pow(g, self.b, p)
        self.A = A
        self.s = df.diffie_hellman(self.p, self.b, self.A)

    def receive_message(self, message):
        self.message = message

    def send_message_to_A(self, A):
        m = oracle.cbc.cbc_encode_with_key(self.message, self.s[:16], 16,
                                           b'A' * 16) + oracle.generate_random_bytes(16)
        A.receive_message(m)


class M_class:
    def __init__(self):
        pass

    def receive_init(self, *args):
        if len(args) == 3:
            self.p = args[0]
            self.g = args[1]
            self.A = args[2]
        else:
            self.B = args[0]

    def transfer_init_to_B(self, B):
        B.receive_init(self.p, self.g, self.p)

    def transfer_init_to_A(self, A):
        A.receive_init(self.p)

    def receive_message(self, message):
        useful_message = message[:-16]
        self.s = df.diffie_hellman(self.p, 1, self.p)
        self.message = oracle.cbc.cbc_decode_with_key(useful_message, self.s, 16, b'A' * 16)
        print(self.message)

    def transfer_message_to_B(self, B):
        B.receive_message(self.message)

    def transfer_message_to_A(self, A):
        A.receive_message(self.message)


def communicate(A, B, message):
    A.init_with_B(B)
    B.init_with_A(A)
    A.send_message_to_B(B, message)
    B.send_message_to_A(A)


def intercept_messages(M, A, B, message):
    A.init_with_B(M)
    M.transfer_init_to_B(B)
    B.init_with_A(M)
    M.transfer_init_to_A(A)
    print(B.g)
    print(B.s)
    A.send_message_to_B(M, message)
    print(M.s)
    M.transfer_message_to_B(B)
    B.send_message_to_A(M)
    M.transfer_message_to_A(A)


def main():
    A = A_class(0xe088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd, 2)
    B = B_class()
    M = M_class()
    intercept_messages(M, A, B, b'YELLOW SUBMARINE' * 10)
    # communicate(A, B, b'Yellow submarine')


if __name__ == '__main__':
    main()
