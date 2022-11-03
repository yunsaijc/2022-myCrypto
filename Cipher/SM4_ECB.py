# SM4-ECB模式
import sys

from myCrypto.Cipher.SM4 import *


class ECB:
    def __init__(self):
        self.result = ""

    def encrypt(self, s, k, op=1):
        """ECB working mode, op == 1 means the encryption"""
        if op == 1:
            s = fill(s)
        l = len(s)
        self.result = ""
        for i in range(0, l, 32):
            self.result += SM4().encrypt(s[i:i + 32], k, op)
        return self.result

    def decrypt(self, s, k):
        """ECB working mode decryption"""
        tmp = self.encrypt(s, k, 0)
        return unFill(tmp)

    def encryptFile(self, inPath, outPath, key):
        try:
            fileIn = open(inPath, 'rb')
            fileOut = open(outPath, 'wb')
        except IOError:
            sys.exit("Wrong file path !!!")
        s = fileIn.read()
        s = s.hex()
        s = self.encrypt(s, key)
        fileOut.write(bytes.fromhex(s))

    def decryptFile(self, inPath, outPath, key):
        try:
            fileIn = open(inPath, 'rb')
            fileOut = open(outPath, 'wb')
        except IOError:
            sys.exit("Wrong file path !!!")
        s = fileIn.read()
        s = s.hex()
        s = self.decrypt(s, key)
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
    s = s[:l - offset]
    return s


if __name__ == '__main__':
    # k = input()[2:].strip()
    # op = int(input())
    #
    # inStr = ""
    # while True:
    #     try:
    #         inStr += input().strip()
    #     except EOFError:
    #         break
    #
    # s = inStr.replace(" ", "")
    # s = s.replace("0x", "")
    # result = ""
    # if op == 1:
    #     result = ECB().encrypt(s, k)
    # elif op == 0:
    #     result = ECB().decrypt(s, k)
    # for i in range(0, len(result), 2):
    #     print("0x" + result[i:i+2], end=' ')
    #     if i > 0 and (i+2) % 32 == 0:
    #         print()
    # print(result)

    inP = "testTxt.txt"
    outP = "testOut"
    inP2 = "testOut"
    outP2 = "testOut2.txt"
    k = "9975af70c80ebc0dd06fcef50cf5d49f"
    ECB().encryptFile(inP, outP, k)
    ECB().decryptFile(inP2, outP2, k)
