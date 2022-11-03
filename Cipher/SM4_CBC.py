# SM4-CBC模式
from myCrypto.Cipher.SM4 import *


class CBC:
    def __init__(self):
        self.result = ""

    def encrypt(self, s, k, IV, op=1):
        """CBC working mode, op == 1 means the encryption"""
        if op == 1:
            s = fill(s)
        l = len(s)
        self.result = ""
        former = IV
        out = ""
        for i in range(0, l, 32):
            string = s[i:i + 32]
            if op == 1:
                string = XOR(former, string)
                out = SM4().encrypt(string, k, op)
                former = out
            elif op == 0:
                tmp = SM4().encrypt(string, k, op)
                out = XOR(tmp, former)
                former = string
            self.result += out
        return self.result

    def decrypt(self, s, k, IV):
        """ECB working mode decryption"""
        tmp = self.encrypt(s, k, IV, 0)
        return unFill(tmp)

    def encryptFile(self, inPath, outPath, key, IV):
        try:
            fileIn = open(inPath, 'rb')
            fileOut = open(outPath, 'wb')
        except IOError:
            sys.exit("Wrong file path !!!")
        s = fileIn.read()
        s = s.hex()
        s = self.encrypt(s, key, IV)
        fileOut.write(bytes.fromhex(s))

    def decryptFile(self, inPath, outPath, key, IV):
        try:
            fileIn = open(inPath, 'rb')
            fileOut = open(outPath, 'wb')
        except IOError:
            sys.exit("Wrong file path !!!")
        s = fileIn.read()
        s = s.hex()
        s = self.decrypt(s, key, IV)
        fileOut.write(bytes.fromhex(s))


def fill(s: str):
    """Fill s, 128 bits as a group (32 hex codes)"""
    l = len(s)
    if l % 32 != 0:
        offset = (32 - l % 32) // 2
        while len(s) % 32 != 0:
            s += format(offset, 'x').zfill(2)
    else:
        s += ("10" * 16)
    return s


def unFill(s):
    """Unfill s"""
    offset = int(s[-2:], 16) * 2
    l = len(s)
    s = s[:l-offset]
    return s


def XOR(a, b):
    """XOR operation between a and b"""
    result = int(a, 16) ^ int(b, 16)
    return format(result, 'x').zfill(32)


if __name__ == '__main__':
    k = input()[2:].strip()
    IV = input()[2:].strip()
    op = int(input())

    inStr = ""
    while True:
        try:
            inStr += input().strip()
        except EOFError:
            break
    s = inStr.replace(" ", "")
    s = s.replace("0x", "")
    # print(s)

    result = ""
    if op == 1:
        result = CBC().encrypt(s, k, IV)
    elif op == 0:
        result = CBC().decrypt(s, k, IV)

    # for i in range(0, len(result), 2):
    #     print("0x" + result[i:i+2], end=' ')
    #     if i > 0 and (i+2) % 32 == 0:
    #         print()
    print(result)

    # inP = "testTxt.txt"
    # outP = "testOut"
    # inP2 = "testOut"
    # outP2 = "testOut2.txt"
    # k = "9975af70c80ebc0dd06fcef50cf5d49f"
    # IV = "a8638d2fb23cc49206edd7c84532eaab"
    # CBC().encryptFile(inP, outP, k, IV)
    # CBC().decryptFile(inP2, outP2, k, IV)
