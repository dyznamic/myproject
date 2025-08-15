import time
from secrets import randbelow
from typing import Optional, Tuple, List
from functools import lru_cache

# SM2椭圆曲线参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (GX, GY)

# SM3哈希常量
SM3_IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

Point = Optional[Tuple[int, int]]


@lru_cache(maxsize=1024)
def mod_inv(a: int, m: int) -> int:
    if a < 0:
        a = (a % m + m) % m

    # 使用扩展欧几里得算法
    old_r, r = a, m
    old_x, x = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x

    if old_r != 1:
        raise ValueError(f"模逆不存在: {a} mod {m}")

    return old_x % m


def is_on_curve(point: Point) -> bool:
    if point is None:  # 无穷远点
        return True

    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_neg(point: Point) -> Point:
    if point is None:
        return None

    x, y = point
    return (x, (-y) % P)


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    # 检查是否为相反的点
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None  # P + (-P) = O
        # 点倍加
        if p1 == p2:
            numerator = (3 * x1 * x1 + A) % P
            denominator = (2 * y1) % P
        else:
            return None
    else:
        numerator = (y2 - y1) % P
        denominator = (x2 - x1) % P


    lambda_val = (numerator * mod_inv(denominator, P)) % P
    x3 = (lambda_val * lambda_val - x1 - x2) % P
    y3 = (lambda_val * (x1 - x3) - y1) % P

    return (x3, y3)


def scalar_mul(k: int, point: Point) -> Point:
    if point is None or k % N == 0:
        return None

    if k < 0:
        return scalar_mul(-k, point_neg(point))

    result = None
    base = point

    while k > 0:
        if k & 1:
            result = point_add(result, base)
        base = point_add(base, base)
        k >>= 1

    return result


# SM3哈希函数
def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF



def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)
def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)
def _ff(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (x & z) | (y & z))
def _gg(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (~x & z))


def sm3_hash(message: bytes) -> bytes:
    # padding
    msg_len = len(message) * 8
    message += b'\x80'

    # 计算填充长度
    k = (448 - (len(message) * 8) % 512) % 512
    message += b'\x00' * (k // 8)
    message += msg_len.to_bytes(8, 'big')


    hash_values = SM3_IV[:]

    # 预计算常数
    t_constants = [0x79CC4519] * 16 + [0x7A879D8A] * 48


    for i in range(0, len(message), 64):
        block = message[i:i + 64]

        # 消息扩展
        w = [int.from_bytes(block[j:j + 4], 'big') for j in range(0, 64, 4)]

        for j in range(16, 68):
            temp = w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)
            w.append((_p1(temp) ^ _rotl(w[j - 13], 7) ^ w[j - 6]) & 0xFFFFFFFF)

        w1 = [(w[j] ^ w[j + 4]) & 0xFFFFFFFF for j in range(64)]

        # 压缩函数
        a, b, c, d, e, f, g, h = hash_values

        for j in range(64):
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t_constants[j], j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)

            tt1 = (_ff(j, a, b, c) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & 0xFFFFFFFF

            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = _p0(tt2)

        # 更新哈希值
        hash_values = [
            (hash_values[i] ^ val) & 0xFFFFFFFF
            for i, val in enumerate([a, b, c, d, e, f, g, h])
        ]

    return b''.join(val.to_bytes(4, 'big') for val in hash_values)


def int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')


def point_to_bytes(point: Point) -> bytes:
    if point is None:
        raise ValueError("无穷远点")

    x, y = point
    return int_to_bytes(x, 32) + int_to_bytes(y, 32)


def compute_za(user_id: bytes, public_key: Point) -> bytes:

    if public_key is None:
        raise ValueError("无穷远点")

    id_len = len(user_id) * 8
    entl = id_len.to_bytes(2, 'big')

    # ZA
    za_input = (entl + user_id +
                int_to_bytes(A, 32) + int_to_bytes(B, 32) +
                int_to_bytes(GX, 32) + int_to_bytes(GY, 32) +
                point_to_bytes(public_key))

    return sm3_hash(za_input)

#生成密钥
def generate_keypair() -> Tuple[int, Point]:
    max_attempts = 1000

    for _ in range(max_attempts):
        private_key = randbelow(N - 1) + 1  # 确保在[1, n-1]范围内
        public_key = scalar_mul(private_key, G)

        if public_key is not None and is_on_curve(public_key):
            return private_key, public_key

    raise RuntimeError("keypair generate error")


def sm2_sign(message: bytes, user_id: bytes, private_key: int) -> Tuple[int, int]:
    if not (1 <= private_key < N):
        raise ValueError("d超出范围")

    public_key = scalar_mul(private_key, G)
    za = compute_za(user_id, public_key)
    e = int.from_bytes(sm3_hash(za + message), 'big') % N

    max_attempts = 1000
    for _ in range(max_attempts):
        k = randbelow(N - 1) + 1  # k在[1, n-1]范围内

        point = scalar_mul(k, G)
        if point is None:
            continue

        x1, _ = point
        r = (e + x1) % N

        if r == 0 or (r + k) % N == 0:
            continue

        # s = (1 + d)^(-1) * (k - r * d) mod n
        s = (mod_inv((1 + private_key) % N, N) * (k - r * private_key)) % N

        if s != 0:
            return r, s

    raise RuntimeError("签名生成失败")


def sm2_verify(message: bytes, user_id: bytes, public_key: Point,
               signature: Tuple[int, int]) -> bool:
    try:
        if public_key is None or not is_on_curve(public_key):
            return False

        r, s = signature
        if not (1 <= r < N and 1 <= s < N):
            return False

        za = compute_za(user_id, public_key)
        e = int.from_bytes(sm3_hash(za + message), 'big') % N

        t = (r + s) % N
        if t == 0:
            return False

        # 计算 (s*G + t*P)
        sg = scalar_mul(s, G)
        tp = scalar_mul(t, public_key)

        if sg is None or tp is None:
            return False

        point = point_add(sg, tp)
        if point is None:
            return False

        x1, _ = point
        return ((e + x1) % N) == r

    except Exception:
        return False


if __name__ == "__main__":
    user_id = b"1234567812345678"
    message = b"Hello, world!"
    try:
        private_key, public_key = generate_keypair()
        print(f"私钥 d = {hex(private_key)}")
        print(f"公钥 P = ({hex(public_key[0])}, {hex(public_key[1])})")
        za = compute_za(user_id, public_key)
        print(f"ZA = {za.hex()}")
        signature = sm2_sign(message, user_id, private_key)
        print(f"签名 r = {hex(signature[0])}")
        print(f"签名 s = {hex(signature[1])}")
        start = time.time()
        for _ in range(100):
            sm2_verify(message, user_id, public_key, signature)
        usetime = time.time() - start
        print("所用时间：", usetime, "秒")
        is_valid = sm2_verify(message, user_id, public_key, signature)
        print(f"验证结果: {'✓ 通过' if is_valid else '✗ 失败'}")
    except Exception as e:
        print(f"错误: {e}")