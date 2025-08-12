#include <iostream>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>

using namespace std;

#define MAX 160000 // 最大明文长度

// big-endian get/put (使用 uint32_t)
#define GET_ULONG_BE(n,b,i) \
    { \
        (n) = ((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i) + 1] << 16) | ((uint32_t)(b)[(i) + 2] << 8) | ((uint32_t)(b)[(i) + 3]); \
    }

#define PUT_ULONG_BE(n,b,i) \
    { \
        (b)[(i)    ] = (unsigned char)((n) >> 24); \
        (b)[(i) + 1] = (unsigned char)((n) >> 16); \
        (b)[(i) + 2] = (unsigned char)((n) >>  8); \
        (b)[(i) + 3] = (unsigned char)((n)      ); \
    }

static const unsigned char Sbox[16][16] = {
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

const uint32_t FK[4] = { 0xA3B1BAC6u, 0x56AA3350u, 0x677D9197u, 0xB27022DCu };
const uint32_t CK[32] = {
    0x00070e15u,0x1c232a31u,0x383f464du,0x545b6269u,0x70777e85u,0x8c939aa1u,0xa8afb6bdu,0xc4cbd2d9u,
    0xe0e7eef5u,0xfc030a11u,0x181f262du,0x343b4249u,0x50575e65u,0x6c737a81u,0x888f969du,0xa4abb2b9u,
    0xc0c7ced5u,0xdce3eaf1u,0xf8ff060du,0x141b2229u,0x30373e45u,0x4c535a61u,0x686f767du,0x848b9299u,
    0xa0a7aeb5u,0xbcc3cad1u,0xd8dfe6edu,0xf4fb0209u,0x10171e25u,0x2c333a41u,0x484f565du,0x646b7279u
};

// 内联旋转（32-bit）
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// T-table: 对 T1 和 T2 各自建立 4 个表，每表 256 项
static uint32_t T1_table[4][256];
static uint32_t T2_table[4][256];
static bool tables_initialized = false;

// 初始化 T 表
void init_T_tables() {
    if (tables_initialized) return;
    for (int pos = 0; pos < 4; ++pos) {
        for (int b = 0; b < 256; ++b) {
            unsigned char sb = Sbox[(b & 0xF0) >> 4][b & 0x0F];
            // 把 sb 放入对应字节位置生成 B
            uint32_t B = ((uint32_t)sb) << (8 * (3 - pos)); // pos=0 -> MSB
            // T1 linear L: B ^ Lrot2 ^ Lrot10 ^ Lrot18 ^ Lrot24
            uint32_t C1 = B ^ rotl32(B, 2) ^ rotl32(B, 10) ^ rotl32(B, 18) ^ rotl32(B, 24);
            T1_table[pos][b] = C1;
            // T2 linear L': B ^ Lrot13 ^ Lrot23
            uint32_t C2 = B ^ rotl32(B, 13) ^ rotl32(B, 23);
            T2_table[pos][b] = C2;
        }
    }
    tables_initialized = true;
}

// 用表实现的 T1 / T2
static inline uint32_t T1_table_lookup(uint32_t X) {
    // 提取四个字节
    uint8_t a0 = (X >> 24) & 0xFF;
    uint8_t a1 = (X >> 16) & 0xFF;
    uint8_t a2 = (X >> 8) & 0xFF;
    uint8_t a3 = (X) & 0xFF;
    return T1_table[0][a0] ^ T1_table[1][a1] ^ T1_table[2][a2] ^ T1_table[3][a3];
}

static inline uint32_t T2_table_lookup(uint32_t X) {
    uint8_t a0 = (X >> 24) & 0xFF;
    uint8_t a1 = (X >> 16) & 0xFF;
    uint8_t a2 = (X >> 8) & 0xFF;
    uint8_t a3 = (X) & 0xFF;
    return T2_table[0][a0] ^ T2_table[1][a1] ^ T2_table[2][a2] ^ T2_table[3][a3];
}

// 轮密钥扩展 (mod==1 表示为解密，翻转 rk)
void setkey(uint32_t rk[32], uint32_t MK[4], uint32_t k[36], int mod) {
    init_T_tables();
    k[0] = MK[0] ^ FK[0];
    k[1] = MK[1] ^ FK[1];
    k[2] = MK[2] ^ FK[2];
    k[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; ++i) {
        // 使用 T2 表查表加速
        k[i + 4] = k[i] ^ T2_table_lookup(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        rk[i] = k[i + 4];
    }
    if (mod) {
        // 翻转 rk
        for (int i = 0; i < 16; ++i) {
            uint32_t tmp = rk[i];
            rk[i] = rk[31 - i];
            rk[31 - i] = tmp;
        }
    }
}

// 一次完整 32 轮变换（使用 T1 表加速）
void round_encrypt(const uint32_t sk[32], const unsigned char input[16], unsigned char output[16]) {
    uint32_t X[36] = { 0 };
    GET_ULONG_BE(X[0], input, 0);
    GET_ULONG_BE(X[1], input, 4);
    GET_ULONG_BE(X[2], input, 8);
    GET_ULONG_BE(X[3], input, 12);
    for (int i = 0; i < 32; ++i) {
        X[i + 4] = X[i] ^ T1_table_lookup(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ sk[i]);
    }
    PUT_ULONG_BE(X[35], output, 0);
    PUT_ULONG_BE(X[34], output, 4);
    PUT_ULONG_BE(X[33], output, 8);
    PUT_ULONG_BE(X[32], output, 12);
}

// CBC 模式加密（padding PKCS#7 风格）
void encode(const unsigned char* src_in, unsigned char* dst, uint32_t MK[4], uint32_t k[36], unsigned char iv[16], size_t& len) {
    init_T_tables();
    uint32_t sk[32];
    setkey(sk, MK, k, 0);

    // PKCS#7 padding
    size_t pad = 16 - (len % 16);
    size_t newlen = len + pad;
    unsigned char* buffer = new unsigned char[newlen];
    memcpy(buffer, src_in, len);
    memset(buffer + len, (unsigned char)pad, pad);

    const unsigned char* src = buffer;
    size_t remaining = newlen;
    while (remaining) {
        unsigned char block[16];
        for (int i = 0; i < 16; ++i) block[i] = src[i] ^ iv[i];
        round_encrypt(sk, block, block);
        memcpy(iv, block, 16);
        memcpy(dst, block, 16);
        dst += 16;
        src += 16;
        remaining -= 16;
    }
    len = newlen;
    delete[] buffer;
}

// CBC 解密
void decode(const unsigned char* src, unsigned char* dst, uint32_t MK[4], uint32_t k[36], unsigned char iv[16], size_t& len) {
    init_T_tables();
    uint32_t sk[32];
    setkey(sk, MK, k, 1); // 解密时 rk 翻转

    unsigned char prev[16];
    memcpy(prev, iv, 16);

    size_t remaining = len;
    const unsigned char* p = src;
    unsigned char tmp[16];
    while (remaining) {
        memcpy(tmp, p, 16);
        round_encrypt(sk, p, dst);
        for (int i = 0; i < 16; ++i) dst[i] ^= prev[i];
        memcpy(prev, tmp, 16);
        dst += 16;
        p += 16;
        remaining -= 16;
    }
    // 去 padding（PKCS#7）
    if (len > 0) {
        unsigned char pad = dst[-1];
        if (pad >= 1 && pad <= 16) {
            len -= pad;
        }
    }
}

// 随机字符串生成
char* rand_str_cstyle(int length) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()`~-_=+[{]{|;:'\",<.>/?";
    static const int CHAR_N = sizeof(chars) - 1;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, CHAR_N - 1);

    char* output = new char[length + 1];
    for (int i = 0; i < length; ++i) {
        output[i] = chars[dist(gen)];
    }
    output[length] = '\0';
    return output;
}

int main() {
    // 初始化表
    init_T_tables();

    uint32_t MK[4] = { 0x01234567u, 0x89abcdefu, 0xfedcba98u, 0x76543210u };
    uint32_t key[36] = { 0 };
    unsigned char iv[16] = { 0 };

    size_t length = MAX; // 明文长度
    unsigned char* ciphertext = new unsigned char[MAX + 32];
    unsigned char* plaintext = new unsigned char[MAX + 32];

    // 随机生成明文
    char* rand_str = rand_str_cstyle((int)length);
    size_t m_len = length;

    auto startTP = chrono::high_resolution_clock::now();
    encode((unsigned char*)rand_str, ciphertext, MK, key, iv, m_len);
    auto endTP = chrono::high_resolution_clock::now();
    cout << "加密所用时间: " << chrono::duration_cast<chrono::microseconds>(endTP - startTP).count() << " 微秒\n";

    // reset iv for decode
    memset(iv, 0, sizeof(iv));
    size_t text_len = m_len;

    auto startTP2 = chrono::high_resolution_clock::now();
    decode(ciphertext, plaintext, MK, key, iv, text_len);
    auto endTP2 = chrono::high_resolution_clock::now();
    cout << "解密所用时间: " << chrono::duration_cast<chrono::microseconds>(endTP2 - startTP2).count() << " 微秒\n";

    // 确保以 C 字符串结尾打印
    if (text_len < MAX + 32) plaintext[text_len] = '\0';
    // cout << "解密结果长度: " << (int)text_len << "\n";

    delete[] rand_str;
    delete[] ciphertext;
    delete[] plaintext;

    return 0;
}
