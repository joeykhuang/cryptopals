import hashlib
import importlib

srp = importlib.import_module("5_diffie_hellman.36_secure_remote_password")


class Client_NP_N(srp.Client):
    def __init__(self, N, email, password, n_multiple):
        super().__init__(N, email, password)
        self.A = n_multiple * self.N

    def receive_init(self, salt, B):
        self.salt = salt
        self.B = B
        self.uH = hashlib.sha256()
        self.uH.update((str(self.A) + str(self.B)).encode())
        self.u = int(self.uH.hexdigest(), 16)
        xH = hashlib.sha256()
        xH.update((self.salt + self.P).encode())
        x = int(xH.hexdigest(), 16)
        S = pow(self.B - self.k * pow(self.g, x, self.N), self.a + self.u * x, self.N)
        print("Client S:", S)
        self.KH = hashlib.sha256()
        self.KH.update(str(0).encode())
        self.K = self.KH.hexdigest()

    def send_message_to_server(self, server):
        server.receive_message(self.K)


class Server(srp.Server):
    def receive_init(self, I, A):
        self.I = I
        self.A = A
        self.uH = hashlib.sha256()
        self.uH.update((str(self.A) + str(self.B)).encode())
        self.u = int(self.uH.hexdigest(), 16)
        S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N)
        print("Server S:", S)
        self.KH = hashlib.sha256()
        self.KH.update(str(S).encode())
        self.K = self.KH.hexdigest()


def main():
    for i in range(0, 10):
        client = Client_NP_N(0xe088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd, "1", "", i)
        server = Server(0xe088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd, "hello")
        srp.communicate(client, server)


if __name__ == '__main__':
    main()
