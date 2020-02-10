import hashlib
import random


class Client:
    def __init__(self, N, email, password):
        self.N = N
        self.g = 2
        self.k = 3
        self.a = random.randint(1, self.N)
        self.A = pow(self.g, self.a, N)
        self.I = email
        self.P = password

    def init_with_server(self, server):
        server.receive_init(self.I, self.A)

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
        self.KH = hashlib.sha256()
        self.KH.update(str(S).encode())
        self.K = self.KH.hexdigest()

    def send_message_to_server(self, server):
        server.receive_message(self.K)


class Server:
    def __init__(self, N, password):
        self.N = N
        self.g = 2
        self.k = 3
        self.P = password
        self.b = random.randint(1, N)
        self.salt = str(random.randint(1, 100000))
        xH = hashlib.sha256()
        xH.update((str(self.salt) + self.P).encode())
        x = int(xH.hexdigest(), 16)
        self.v = pow(self.g, x, self.N)
        self.B = self.k * self.v + pow(self.g, self.b, self.N)

    def init_with_client(self, client):
        client.receive_init(self.salt, self.B)

    def receive_init(self, I, A):
        self.I = I
        self.A = A
        self.uH = hashlib.sha256()
        self.uH.update((str(self.A) + str(self.B)).encode())
        self.u = int(self.uH.hexdigest(), 16)
        S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N)
        self.KH = hashlib.sha256()
        self.KH.update(str(S).encode())
        self.K = self.KH.hexdigest()

    def receive_message(self, client_K):
        if self.K == client_K:
            print("OK")


def communicate(client, server):
    client.init_with_server(server)
    print("Init done with server")
    server.init_with_client(client)
    print("Init done with client")
    client.send_message_to_server(server)


def main():
    client = Client(0xe088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd, "1", "hello")
    server = Server(0xe088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd, "hello")
    communicate(client, server)


if __name__ == '__main__':
    main()
