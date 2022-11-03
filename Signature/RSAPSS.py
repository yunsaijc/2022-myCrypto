# RSA-PSS数字签名算法

from hashlib import sha1
from math import ceil


class RSA_PSS_Sign:
    def __init__(self, e=0, d=0, n=0):
        self.e = e
        self.d = d
        self.n = n

    def sign(self, M: str, emBits: int, salt: str):
        sLen, hLen = 20, 20
        emLen = ceil(emBits / 8)
        pad1 = "00" * 8
        pad2 = "00" * (emLen - sLen - hLen - 2) + "01"
        mHash = sha1(M.encode()).hexdigest()
        M2 = pad1 + mHash + salt
        H = sha1(bytes.fromhex(M2)).hexdigest()
        DB = pad2 + salt
        dbMask = MGF(H, emLen - hLen - 1)
        maskedDB = XOR(DB, dbMask, len(dbMask))
        idx = (8 * emLen - emBits) // 4
        maskedDB = "0" * idx + maskedDB[idx:]
        EM = maskedDB + H + "bc"
        k = len(bin(self.n)[2:]) // 4
        s = pow(int(EM, 16), self.d, self.n)
        result = format(s, 'x').zfill(k)
        return result

    def verify(self, M: str, emBits: int, S: str):
        sLen, hLen = 20, 20
        m = pow(int(S, 16), self.e, self.n)
        emLen = ceil(emBits / 8)
        EM = format(m, 'x').zfill(emLen * 2)
        pad1 = "00" * 8
        pad2 = "00" * (emLen - sLen - hLen - 2) + "01"
        mHash = sha1(M.encode()).hexdigest()
        if emLen < hLen + sLen + 2:
            return False
        if EM[-2:] != "bc":
            return False
        maskedDB = EM[:(emLen-hLen-1)*2]
        H = EM[(emLen-hLen-1)*2:(emLen-hLen-1)*2 + hLen*2]
        for ch in maskedDB[:(8*emLen-emBits)//4]:
            if ch != '0':
                return False
        dbMask = MGF(H, emLen-hLen-1)
        DB = XOR(maskedDB, dbMask, len(dbMask))
        idx = 8 * emLen - emBits
        tmp = format(int(DB[:2], 16), 'b').zfill(8)
        DB = format(int("0"*idx + tmp[idx:]), 'x').zfill(2) + DB[2:]
        if DB[:(emLen-hLen-sLen-1)*2] != pad2:
            return False
        salt = DB[-(sLen*2):]
        M2 = pad1 + mHash + salt
        H2 = sha1(bytes.fromhex(M2)).hexdigest()
        return H == H2


def MGF(x: str, maskLen: int):
    T = ""
    hLen = 20
    k = ceil(maskLen / hLen) - 1
    for i in range(k+1):
        tmp = format(i, 'x').zfill(8)
        T += sha1(bytes.fromhex(x+tmp)).hexdigest()
    return T[:maskLen*2]


def XOR(a, b, l):
    return format(int(a, 16) ^ int(b, 16), 'x').zfill(l)


if __name__ == '__main__':
    M = input()
    n = int(input())
    emBits = int(input())
    Mode = input().strip()
    if Mode == "Sign":
        d = int(input())
        salt = input()
        result = RSA_PSS_Sign(d=d, n=n).sign(M, emBits, salt)
    elif Mode == "Vrfy":
        e = int(input())
        S = input()
        result = RSA_PSS_Sign(e=e, n=n).verify(M, emBits, S)
    print(result)
    # 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014758a1c40f6ead39d8281779d63e0bd5377f19a5
    # 012efac302e49c30be37501ca2223d7d4528015f25f04b05b4443d2947a774615570184bd5a4e9725dfcc89e7e66f555c62bc28c854a4f313933c83f7610c072f34ee39d5fc3a14d334ab66f1d65c2def4638fcbd0ac6b54a9367cbf045da89d5e006037512f0af7
    # 012efac302e49c30be37501ca2223d7d4528015f25f04b05b4443d2947a774615570184bd5a4e9725dfcc89e7e66f555c62bc28c854a4f313933c83f7610c072f34ee39d5fc3a14d334ab66f1d65c2def4638fca97f4ca90a658d186dc75bfe4883e6be266501352
