"""
    Number.py
"""
import math
import random


def getPrime(n):
    """
    getPrime(n: int): long
    Return a random n-bit prime number.
    """
    num = getInteger(n) | 1
    while not MillerRabinTest(num, 50):
        num += 2
    return num


def getInteger(n):
    """
    getInteger(n: int): long
    Return a random n-bit integer.
    """
    low = pow(2, n - 1)
    high = pow(2, n) - 1
    return random.randint(low, high)


def long2bytes(n: int):
    """
    long2bytes(n: long): bytes
    Convert an integer to a byte string.
    """
    length = math.ceil((len(bin(n))-2)/8)
    return n.to_bytes(length, byteorder='big')


def bytes2long(s: bytes):
    """
    bytes2long(s: bytes): bytes
    Convert a byte string to an integer.
    """
    return int.from_bytes(s, byteorder='big')


def inverse(a, m):
    """
    inverse(a: long, m: long): long
    Return the inverse of a mod m.
    """
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def fastPow(a, b, m):
    """
    fastPow(a: long, b: long, m: long): long
    Return the result of a^b mod m.
    """
    ans = 1
    while b > 0:
        if b % 2 == 1:
            ans = (ans * a) % m
        b = b >> 1
        a = (a * a) % m
    return ans


def gcd(a, b):
    """
    gcd(a: long, b: long): long
    Return the gcd of a and b
    """
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def MillerRabinTest(n, rounds):
    """
    MillerRabinTest(n: long, rounds: int): bool
    Return False when n is not a prime number.
    """
    isPrime = True
    for a in range(2, rounds + 2):
        if gcd(a, n) != 1:
            continue
        if not MR(a, n):
            isPrime = False
            break
    return isPrime


def MR(a, n):
    """Miller-Rabin, when n is not a prime, return False"""
    q = n - 1
    k = 0
    while q % 2 == 0:
        q = q // 2
        k += 1
    if pow(a, q, n) == 1:
        return True
    for j in range(0, k):
        if pow(a, (pow(2, j) * q), n) == n - 1:
            return True
    return False
