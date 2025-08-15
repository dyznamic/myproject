import time
from secrets import randbelow
from typing import Optional, Tuple


p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G  = (Gx, Gy)


def egcd(a_: int, b_: int) -> Tuple[int, int, int]:
    old_r, r = a_, b_
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y

def mod_inv(a_: int, m: int) -> int:
    a_ %= m
    g, x, _ = egcd(a_, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m

Point = Optional[Tuple[int, int]]  # use None as point-at-infinity

def is_on_curve(P: Point) -> bool:
    if P is None:
        return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

def point_neg(P: Point) -> Point:
    if P is None:
        return None
    x, y = P
    return (x, (-y) % p)

def point_add(P: Point, Q: Point) -> Point:

    if P is None: return Q
    if Q is None: return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # P + (-P) = O

    if P == Q:
        # lambda = (3*x1^2 + a) / (2*y1)
        num = (3 * x1 * x1 + a) % p
        den = mod_inv((2 * y1) % p, p)
        lam = (num * den) % p
    else:
        # lambda = (y2 - y1) / (x2 - x1)
        num = (y2 - y1) % p
        den = mod_inv((x2 - x1) % p, p)
        lam = (num * den) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mul(k: int, P: Point) -> Point:

    if P is None or k % n == 0:
        return None
    if k < 0:
        return scalar_mul(-k, point_neg(P))
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R


def _rotl(x: int, n_: int) -> int:
    return ((x << n_) | (x >> (32 - n_))) & 0xFFFFFFFF

def _P0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)

def _P1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def _FF(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (x & z) | (y & z))

def _GG(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (~x & z))

_IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

def sm3(msg: bytes) -> bytes:

    # Padding
    l = len(msg) * 8
    msg1 = msg + b'\x80'
    k = (448 - (len(msg1) * 8) % 512) % 512
    msg1 += b'\x00' * (k // 8)
    msg1 += l.to_bytes(8, 'big')

    # Iterate
    V = _IV[:]
    T_j = [0x79CC4519] * 16 + [0x7A879D8A] * 48

    for i in range(0, len(msg1), 64):
        B = msg1[i:i+64]
        W = [int.from_bytes(B[j:j+4], 'big') for j in range(0, 64, 4)]
        for j in range(16, 68):
            Wj = _P1(W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)) ^ _rotl(W[j-13], 7) ^ W[j-6]
            W.append(Wj & 0xFFFFFFFF)
        W1 = [(W[j] ^ W[j+4]) & 0xFFFFFFFF for j in range(64)]

        A, B_, C, D, E, F, G_, H = V
        for j in range(64):
            SS1 = _rotl((_rotl(A, 12) + E + _rotl(T_j[j], j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ _rotl(A, 12)
            TT1 = (_FF(j, A, B_, C) + D + SS2 + W1[j]) & 0xFFFFFFFF
            TT2 = (_GG(j, E, F, G_) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = _rotl(B_, 9)
            B_ = A
            A = TT1
            H = G_
            G_ = _rotl(F, 19)
            F = E
            E = _P0(TT2)

        V = [a ^ b for a, b in zip(V, [A, B_, C, D, E, F, G_, H])]

    out = b''.join(v.to_bytes(4, 'big') for v in V)
    return out

def int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')

def xy_to_bytes(P: Point) -> bytes:
    if P is None:
        raise ValueError("Point at infinity has no coordinates")
    x, y = P
    return int_to_bytes(x, 32) + int_to_bytes(y, 32)

def compute_ZA(ID: bytes, P: Point) -> bytes:

    if P is None:
        raise ValueError("public key is point-at-infinity")
    ENTL = (len(ID) * 8).to_bytes(2, 'big')
    Z_input = (
        ENTL + ID +
        int_to_bytes(a, 32) + int_to_bytes(b, 32) +
        int_to_bytes(Gx, 32) + int_to_bytes(Gy, 32) +
        xy_to_bytes(P)
    )
    return sm3(Z_input)

def gen_keypair() -> Tuple[int, Point]:

    while True:
        d = randbelow(n)
        if 1 <= d < n:
            P = scalar_mul(d, G)
            if P is not None and is_on_curve(P):
                return d, P

def sm2_sign(M: bytes, ID: bytes, d: int) -> Tuple[int, int]:

    if not (1 <= d < n):
        raise ValueError("bad private key")

    # e
    ZA = compute_ZA(ID, scalar_mul(d, G))
    e = int.from_bytes(sm3(ZA + M), 'big')

    while True:
        k = randbelow(n)
        if k == 0:
            continue
        x1y1 = scalar_mul(k, G)
        if x1y1 is None:
            continue
        x1, _ = x1y1
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            continue
        s = (mod_inv(1 + d, n) * (k - r * d)) % n
        if s != 0:
            return r, s

def sm2_verify(M: bytes, ID: bytes, P: Point, sig: Tuple[int, int]) -> bool:

    if P is None or not is_on_curve(P):
        return False

    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return False

    ZA = compute_ZA(ID, P)
    e = int.from_bytes(sm3(ZA + M), 'big')

    t = (r + s) % n
    if t == 0:
        return False

    sG = scalar_mul(s, G)
    tP = scalar_mul(t, P)
    if sG is None and tP is None:
        return False
    x1y1 = point_add(sG, tP)
    if x1y1 is None:
        return False

    x1, _ = x1y1
    R = (e + x1) % n
    return R == r


if __name__ == "__main__":

    ID = b"1234567812345678"
    message = b"Hello, world!"

    d, P = gen_keypair()
    print("私钥 d =", hex(d))
    print("公钥 P =", (hex(P[0]), hex(P[1])))
    ZA = compute_ZA(ID, P)
    print("计算哈希值：", ZA.hex())
    sig = sm2_sign(message, ID, d)
    print("签名结果 r =", hex(sig[0]))
    print("s =", hex(sig[1]))
    start = time.time()
    for _ in range(100):
        sm2_verify(message, ID, P, sig)
    usetime = time.time() - start
    result = sm2_verify(message, ID, P, sig)
    print("验证 =", result)
    print("所用时间：",usetime,"秒")