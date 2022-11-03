# SHA-1 Hash
import copy
import sys


class SHA1:
    def __init__(self):
        self.msg = ""
        self.msgLen = 0
        self.MD = [0x67452301, 0xefcdab89,
                   0x98badcfe, 0x10325476,
                   0xc3d2e1f0]
        self.curGrp = ""
        self.W = []
        self.K = [0x5A827999, 0x6ED9EBA1,
                  0x8F1BBCDC, 0xCA62C1D6]
        self.result = ""

    def hexDigest(self, msg: bytes):
        self.msg = msg.hex()
        self.msgLen = len(self.msg) * 4
        self.get()
        return self.result

    def fileHexDigest(self, inPath):
        try:
            fileIn = open(inPath, 'rb')
        except IOError:
            sys.exit("Wrong file path !!!")
        s = fileIn.read()
        s = s.hex()
        return self.hexDigest(s.encode())

    def get(self):
        self.fillBit()
        self.fillLen()
        # print("mbStr:\n" + format(int(self.msg, 16), 'b').zfill(512))
        while True:
            self.curGrp = self.msg[:128]
            if len(self.curGrp) == 0:
                break
            # print("curGrp:\n" + self.curGrp)
            self.round()
            self.msg = self.msg[128:]
        for i in range(5):
            self.result += format(self.MD[i], 'x').zfill(8)
        # self.show()

    def fillBit(self):
        if self.msgLen % 512 == 448:
            self.msg = self.msg + "8" + "0" * 127
        else:
            tmpBin = format(int(self.msg, 16), 'b')
            while len(tmpBin) % 4 != 0:
                tmpBin = "0" + tmpBin
            tmpBin += "1"
            while len(tmpBin) % 512 != 448:
                tmpBin += "0"
            self.msg = format(int(tmpBin, 2), 'x')

    def fillLen(self):
        self.msg += format(self.msgLen, 'x').zfill(16)

    def getW(self):
        self.W = []
        for i in range(16):
            self.W.append(int(self.curGrp[8*i:8*(i+1)], 16))
        for i in range(16, 80):
            self.W.append(S(self.W[i-16] ^ self.W[i-14] ^
                            self.W[i-8] ^ self.W[i-3], 1))

    def round(self):
        self.getW()
        # print("W:")
        # for i in range(len(self.W)):
        #     print(i, end='\t')
        #     print(format(self.W[i], 'b').zfill(32))
        former = copy.deepcopy(self.MD)
        for i in range(80):
            A = self.MD[0]
            B = self.MD[1]
            C = self.MD[2]
            D = self.MD[3]
            E = self.MD[4]
            # if i == 1:
            #     A = 0b11110011000110000000000100100010
            #     B = 0b01100111010001010010001100000001
            #     C = 0b01111011111100110110101011100010
            #     D = 0b10011000101110101101110011111110
            #     E = 0b00010000001100100101010001110110
            newA = (E + f(B, C, D, i // 20) + S(A, 5) + self.W[i] + self.K[i // 20]) % pow(2, 32)
            self.MD[4] = D
            self.MD[3] = C
            self.MD[2] = S(B, 30)
            self.MD[1] = A
            self.MD[0] = newA
            # print('Round: {:d}'.format(i+1))
            # for j in range(5):
            #     print(format(self.MD[j], 'b').zfill(32))
            # print()
        for i in range(5):
            self.MD[i] = (self.MD[i] + former[i]) % pow(2, 32)

    def show(self):
        print(self.result)


def f(b: int, c: int, d: int, i: int):
    if i == 0:
        return (b & c) | ((~b) & d)
    elif i == 1 or i == 3:
        return b ^ c ^ d
    elif i == 2:
        return (b & c) | (b & d) | (c & d)


def S(num: int, offset: int):
    tmpBin = format(num, 'b').zfill(32)
    Bin = tmpBin[offset:] + tmpBin[:offset]
    return int(Bin, 2)


if __name__ == '__main__':
    M = input().strip().encode()
    dig = SHA1().hexDigest(M)
    # dig = SHA1().fileHexDigest("/Users/jc02/Desktop/密码学实验/大作业/密码学实验课大作业.pdf")
    print(dig)
