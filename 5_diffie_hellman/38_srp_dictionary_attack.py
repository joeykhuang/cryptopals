import hashlib
import importlib

srp = importlib.import_module("5_diffie_hellman.36_secure_remote_password")


class MITM(srp.Client):

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
