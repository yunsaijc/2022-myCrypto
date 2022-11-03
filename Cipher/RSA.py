# RSA
import sys

from myCrypto.Math.Number import *


class RSA:
    def __init__(self, s):
        if type(s) != int:
            sys.exit("Wrong parameter !!!")
        self.s = s
        self.d = 0
        self.e = 0
        self.N = 0
        self.result = 0

    def encrypt(self):
        """Encrypt plaintext s"""
        self.result = pow(self.s, self.e, self.N)
        return self.result

    def decrypt(self):
        self.result = pow(self.s, self.d, self.N)
        return self.result

    def getKey(self):
        """Generate keys: p, q, N, e and d"""
        p = getPrime(1024)
        q = getPrime(1024)
        self.N = p * q
        self.e = getPrime(1024)
        self.d = inverse(self.e, (p-1) * (q-1))
        print("p: {:d}\nq: {:d}\nN: {:d}\ne: {:d}\nd: {:d}"
              .format(p, q, self.N, self.e, self.d))


if __name__ == '__main__':
    # p = int(input())
    # q = int(input())
    # e = int(input())
    # m = int(input())
    # op = int(input())
    # N = p * q
    # d = inverse(e, (p-1)*(q-1))
    #
    # if op == 1:
    #     print(RSA().encrypt(m))
    # else:
    #     print(RSA().decrypt(m))
    t = RSA(17)
    t.getKey()
    print(t.encrypt())
