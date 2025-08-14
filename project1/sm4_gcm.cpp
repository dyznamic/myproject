#include <iostream>
#include <chrono>
#include <cstring>
#include <random>
#include <cstdint>

using namespace std;

#define MAX 160000 //最大明文长度

// 大端转换宏
#define GET_ULONG_BE(n,b,i) \
    { (n) = ((unsigned long)(b)[(i)] << 24) | ((unsigned long)(b)[(i)+1] << 16) | ((unsigned long)(b)[(i)+2] << 8) | ((unsigned long)(b)[(i)+3]); }

#define PUT_ULONG_BE(n,b,i) \
    { (b)[(i)]   = (unsigned char)((n) >> 24); (b)[(i)+1] = (unsigned char)((n) >> 16); (b)[(i)+2] = (unsigned char)((n) >> 8); (b)[(i)+3] = (unsigned char)((n)); }

// Sbox 
const unsigned char Sbox[16][16] = {
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
const unsigned int FK[4] = { 0xA3B1BAC6u,0x56AA3350u,0x677D9197u,0xB27022DCu };
const unsigned int CK[32] = {
    0x00070e15u,0x1c232a31u,0x383f464du,0x545b6269u,0x70777e85u,0x8c939aa1u,0xa8afb6bdu,0xc4cbd2d9u,
    0xe0e7eef5u,0xfc030a11u,0x181f262du,0x343b4249u,0x50575e65u,0x6c737a81u,0x888f969du,0xa4abb2b9u,
    0xc0c7ced5u,0xdce3eaf1u,0xf8ff060du,0x141b2229u,0x30373e45u,0x4c535a61u,0x686f767du,0x848b9299u,
    0xa0a7aeb5u,0xbcc3cad1u,0xd8dfe6edu,0xf4fb0209u,0x10171e25u,0x2c333a41u,0x484f565du,0x646b7279u
};

// 左移函数
unsigned int leftshift(unsigned int X, unsigned int len)
{
    return (X >> (sizeof(unsigned int) * 8 - len) | (X << len));
}


// T1_table 用于 round（Sbox + L），T2_table 用于密钥扩展（Sbox + L'）
static uint32_t T1_table[4][256];
static uint32_t T2_table[4][256];
static bool tables_inited = false;

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void init_T_tables() {
    if (tables_inited) return;
    for (int pos = 0; pos < 4; ++pos) {
        for (int b = 0; b < 256; ++b) {
            unsigned char sb = Sbox[(b & 0xF0) >> 4][b & 0x0F];
            uint32_t B = ((uint32_t)sb) << (8 * (3 - pos)); // pos=0 -> MSB
            // T1: B ^ (B<<<2) ^ (B<<<10) ^ (B<<<18) ^ (B<<<24)
            uint32_t C1 = B ^ rotl32(B, 2) ^ rotl32(B, 10) ^ rotl32(B, 18) ^ rotl32(B, 24);
            // T2: B ^ (B<<<13) ^ (B<<<23)
            uint32_t C2 = B ^ rotl32(B, 13) ^ rotl32(B, 23);
            T1_table[pos][b] = C1;
            T2_table[pos][b] = C2;
        }
    }
    tables_inited = true;
}

void setkey_ttable(unsigned int rk[32], unsigned int MK[4], unsigned int k[36], int mod)
{
    init_T_tables();
    k[0] = MK[0] ^ FK[0];
    k[1] = MK[1] ^ FK[1];
    k[2] = MK[2] ^ FK[2];
    k[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++)
    {
        unsigned int tmp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
        unsigned char a0 = (tmp >> 24) & 0xFF;
        unsigned char a1 = (tmp >> 16) & 0xFF;
        unsigned char a2 = (tmp >> 8) & 0xFF;
        unsigned char a3 = tmp & 0xFF;
        unsigned int t = T2_table[0][a0] ^ T2_table[1][a1] ^ T2_table[2][a2] ^ T2_table[3][a3];
        k[i + 4] = k[i] ^ t;
        rk[i] = k[i + 4];
    }
    if (mod) {
        for (int i = 0; i < 16; ++i) {
            unsigned int temp = rk[i];
            rk[i] = rk[31 - i];
            rk[31 - i] = temp;
        }
    }
}


void sm4_encrypt_block_ttable(const unsigned int rk[32], const unsigned char input[16], unsigned char output[16])
{
    unsigned int X[36];
    GET_ULONG_BE(X[0], input, 0);
    GET_ULONG_BE(X[1], input, 4);
    GET_ULONG_BE(X[2], input, 8);
    GET_ULONG_BE(X[3], input, 12);
    for (int i = 0; i < 32; ++i) {
        unsigned int tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
        unsigned char a0 = (tmp >> 24) & 0xFF;
        unsigned char a1 = (tmp >> 16) & 0xFF;
        unsigned char a2 = (tmp >> 8) & 0xFF;
        unsigned char a3 = tmp & 0xFF;
        unsigned int t = T1_table[0][a0] ^ T1_table[1][a1] ^ T1_table[2][a2] ^ T1_table[3][a3];
        X[i + 4] = X[i] ^ t;
    }
    PUT_ULONG_BE(X[35], output, 0);
    PUT_ULONG_BE(X[34], output, 4);
    PUT_ULONG_BE(X[33], output, 8);
    PUT_ULONG_BE(X[32], output, 12);
}

static inline void inc32(unsigned char ctr[16]) {
    unsigned long t;
    GET_ULONG_BE(t, ctr, 12);
    t = (t + 1u) & 0xFFFFFFFFu;
    PUT_ULONG_BE(t, ctr, 12);
}

void gf128_mul_be(const unsigned char X[16], const unsigned char Y[16], unsigned char out[16]) {
    const unsigned char R[16] = {
        0xE1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    };
    unsigned char V[16]; memcpy(V, Y, 16);
    unsigned char Z[16]; memset(Z, 0, 16);

    for (int i = 0; i < 128; ++i) {
        int byte_idx = i >> 3;
        int bit_idx = 7 - (i & 7);
        unsigned char bit = (X[byte_idx] >> bit_idx) & 1u;
        if (bit) {
            for (int j = 0; j < 16; ++j) Z[j] ^= V[j];
        }
        unsigned char lsb = V[15] & 1u;
        unsigned char carry = 0;
        for (int j = 0; j < 16; ++j) {
            unsigned char nj = V[j];
            unsigned char new_carry = nj & 1u;
            unsigned char shifted = (nj >> 1) | (carry << 7);
            V[j] = shifted;
            carry = new_carry;
        }
        if (lsb) {
            for (int j = 0; j < 16; ++j) V[j] ^= R[j];
        }
    }
    memcpy(out, Z, 16);
}

static inline void ghash_block(unsigned char Y[16], const unsigned char H[16], const unsigned char block[16]) {
    unsigned char tmp[16];
    for (int i = 0; i < 16; ++i) tmp[i] = Y[i] ^ block[i];
    unsigned char res[16];
    gf128_mul_be(tmp, H, res);
    memcpy(Y, res, 16);
}

void ghash_update(unsigned char Y[16], const unsigned char H[16], const unsigned char* data, size_t len) {
    while (len >= 16) {
        ghash_block(Y, H, data);
        data += 16; len -= 16;
    }
    if (len) {
        unsigned char last[16]; memset(last, 0, 16);
        memcpy(last, data, len);
        ghash_block(Y, H, last);
    }
}

//  SM4-GCM
struct SM4GCM {
    unsigned int rk[32];
    unsigned int ktmp[36];
    unsigned char H[16]; // hash subkey
    unsigned char J0[16]; // IV||0x00000001
};

void sm4gcm_init(SM4GCM& ctx, unsigned int MK[4], const unsigned char iv12[12]) {
    setkey_ttable(ctx.rk, MK, ctx.ktmp, 0);
    unsigned char zero[16]; memset(zero, 0, 16);
    sm4_encrypt_block_ttable(ctx.rk, zero, ctx.H); // H = E_k(0)
    memcpy(ctx.J0, iv12, 12);
    ctx.J0[12] = 0; ctx.J0[13] = 0; ctx.J0[14] = 0; ctx.J0[15] = 1;
}

void sm4gcm_encrypt(const SM4GCM& ctx, const unsigned char* aad, size_t aad_len,
    const unsigned char* pt, size_t pt_len,
    unsigned char* ct, unsigned char tag[16]) {

    // CTR encrypt
    unsigned char counter[16]; memcpy(counter, ctx.J0, 16); inc32(counter);
    size_t off = 0;
    while (off + 16 <= pt_len) {
        unsigned char ks[16];
        sm4_encrypt_block_ttable(ctx.rk, counter, ks);
        for (int i = 0; i < 16; ++i) ct[off + i] = pt[off + i] ^ ks[i];
        inc32(counter); off += 16;
    }
    if (off < pt_len) {
        unsigned char ks[16];
        sm4_encrypt_block_ttable(ctx.rk, counter, ks);
        size_t rem = pt_len - off;
        for (size_t i = 0; i < rem; ++i) ct[off + i] = pt[off + i] ^ ks[i];
    }

    // GHASH over A || C
    unsigned char Y[16]; memset(Y, 0, 16);
    if (aad_len) ghash_update(Y, ctx.H, aad, aad_len);
    if (pt_len)  ghash_update(Y, ctx.H, ct, pt_len);

    // len block
    unsigned char len_block[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)pt_len * 8;
    for (int i = 0; i < 8; i++) len_block[i] = (unsigned char)((aad_bits >> (56 - 8 * i)) & 0xFF);
    for (int i = 0; i < 8; i++) len_block[8 + i] = (unsigned char)((ct_bits >> (56 - 8 * i)) & 0xFF);
    ghash_block(Y, ctx.H, len_block);

    // Tag = E(K, J0) ^ Y
    unsigned char EJ0[16];
    sm4_encrypt_block_ttable(ctx.rk, ctx.J0, EJ0);
    for (int i = 0; i < 16; i++) tag[i] = EJ0[i] ^ Y[i];
}

bool sm4gcm_decrypt_and_verify(const SM4GCM& ctx, const unsigned char* aad, size_t aad_len,
    const unsigned char* ct, size_t ct_len,
    unsigned char* pt, const unsigned char tag[16]) {
    // GHASH over A || C
    unsigned char Y[16]; memset(Y, 0, 16);
    if (aad_len) ghash_update(Y, ctx.H, aad, aad_len);
    if (ct_len)  ghash_update(Y, ctx.H, ct, ct_len);

    unsigned char len_block[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) len_block[i] = (unsigned char)((aad_bits >> (56 - 8 * i)) & 0xFF);
    for (int i = 0; i < 8; i++) len_block[8 + i] = (unsigned char)((ct_bits >> (56 - 8 * i)) & 0xFF);
    ghash_block(Y, ctx.H, len_block);

    // expected tag
    unsigned char EJ0[16];
    sm4_encrypt_block_ttable(ctx.rk, ctx.J0, EJ0);
    unsigned char expected[16];
    for (int i = 0; i < 16; i++) expected[i] = EJ0[i] ^ Y[i];

    unsigned char diff = 0;
    for (int i = 0; i < 16; i++) diff |= (expected[i] ^ tag[i]);
    if (diff != 0) return false;

    // CTR decrypt
    unsigned char counter[16]; memcpy(counter, ctx.J0, 16); inc32(counter);
    size_t off = 0;
    while (off + 16 <= ct_len) {
        unsigned char ks[16];
        sm4_encrypt_block_ttable(ctx.rk, counter, ks);
        for (int i = 0; i < 16; i++) pt[off + i] = ct[off + i] ^ ks[i];
        inc32(counter); off += 16;
    }
    if (off < ct_len) {
        unsigned char ks[16];
        sm4_encrypt_block_ttable(ctx.rk, counter, ks);
        size_t rem = ct_len - off;
        for (size_t i = 0; i < rem; i++) pt[off + i] = ct[off + i] ^ ks[i];
    }
    return true;
}

//随机字符串生成
char* rand_str_cstyle(int length) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()`~-_=+[{]{|;:'\",<.>/?";
    std::random_device rd;
    std::mt19937 generator(rd());
    char* output = new char[length + 1];
    int index = 0;
    while (index < length) {
        auto randNumb = generator();
        while (randNumb > 93 && index < length) {
            output[index++] = chars[randNumb % 93];
            randNumb /= 93;
        }
    }
    output[length] = '\0';
    return output;
}

int main()
{
    // 初始化 T-tables
    init_T_tables();

    unsigned int MK[4] = { 0x01234567u, 0x89abcdefu, 0xfedcba98u, 0x76543210u };
    unsigned char iv12[12] = { 0 }; for (int i = 0; i < 12; i++) iv12[i] = (unsigned char)i;

    // AAD 示例
    size_t aad_len = 128;
    unsigned char* aad = new unsigned char[aad_len];
    for (size_t i = 0; i < aad_len; i++) aad[i] = (unsigned char)(i & 0xFF);

    // 明文
    size_t pt_len = MAX;
    char* rand_plain = rand_str_cstyle((int)pt_len);
    unsigned char* pt = new unsigned char[pt_len];
    memcpy(pt, rand_plain, pt_len);

    unsigned char* ct = new unsigned char[pt_len];
    unsigned char* pt2 = new unsigned char[pt_len];
    unsigned char tag[16];

    SM4GCM ctx;
    sm4gcm_init(ctx, MK, iv12);

    auto t0 = chrono::high_resolution_clock::now();
    sm4gcm_encrypt(ctx, aad, aad_len, pt, pt_len, ct, tag);
    auto t1 = chrono::high_resolution_clock::now();
    cout << "SM4-GCM(T-table) 加密耗时: " << chrono::duration_cast<chrono::microseconds>(t1 - t0).count() << " 微秒\n";

    auto t2 = chrono::high_resolution_clock::now();
    bool ok = sm4gcm_decrypt_and_verify(ctx, aad, aad_len, ct, pt_len, pt2, tag);
    auto t3 = chrono::high_resolution_clock::now();
    cout << "SM4-GCM(T-table) 解密+验证耗时: " << chrono::duration_cast<chrono::microseconds>(t3 - t2).count() << " 微秒\n";

    cout << "Tag 验证: " << (ok ? "OK" : "FAIL") << "\n";
    if (ok && memcmp(pt, pt2, pt_len) == 0) cout << "Plaintext 恢复正确\n";
    else cout << "Plaintext 不一致\n";

    delete[] aad;
    delete[] pt; delete[] ct; delete[] pt2; delete[] rand_plain;
    return 0;
}
