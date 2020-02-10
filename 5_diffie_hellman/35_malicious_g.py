import importlib

mitm = importlib.import_module("5_diffie_hellman.34_mitm_diffie_hellman")


class M_class_1(mitm.M_class):
    def transfer_init_to_B(self, B):
        B.receive_init(self.p, 1, self.A)

    def receive_message(self, message):
        useful_message = message[:-16]
        self.s = mitm.df.diffie_hellman(self.p, 1, 1)
        print(self.s)
        self.message = mitm.oracle.cbc.cbc_decode_with_key(useful_message, self.s, 16, b'A' * 16)
        print(self.message)


def main():
    A = mitm.A_class(0xe088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd, 2)
    B = mitm.B_class()
    M = M_class_1()
    mitm.intercept_messages(M, A, B, b'YELLOW SUBMARINE' * 10)


if __name__ == '__main__':
    main()
