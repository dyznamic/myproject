#include <immintrin.h>
#include <iostream>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <cstdlib>


#include <malloc.h>
static inline void* aligned_malloc(size_t alignment, size_t size) {
    return _aligned_malloc(size, alignment); 
}
static inline void aligned_free(void* ptr) {
    _aligned_free(ptr);
}


using namespace std;

#define MAX 160000

// big-endian get/put (使用 uint32_t)
#define GET_ULONG_BE(n,b,i) \
    { (n) = ((uint32_t)(b)[(i)]<<24) | ((uint32_t)(b)[(i)+1]<<16) | ((uint32_t)(b)[(i)+2]<<8) | ((uint32_t)(b)[(i)+3]); }

#define PUT_ULONG_BE(n,b,i) \
    { (b)[(i)]=(unsigned char)((n)>>24); (b)[(i)+1]=(unsigned char)((n)>>16); (b)[(i)+2]=(unsigned char)((n)>>8); (b)[(i)+3]=(unsigned char)((n)); }

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

const uint32_t FK[4] = { 0xA3B1BAC6u,0x56AA3350u,0x677D9197u,0xB27022DCu };
const uint32_t CK[32] = {
    0x00070e15u,0x1c232a31u,0x383f464du,0x545b6269u,0x70777e85u,0x8c939aa1u,0xa8afb6bdu,0xc4cbd2d9u,
    0xe0e7eef5u,0xfc030a11u,0x181f262du,0x343b4249u,0x50575e65u,0x6c737a81u,0x888f969du,0xa4abb2b9u,
    0xc0c7ced5u,0xdce3eaf1u,0xf8ff060du,0x141b2229u,0x30373e45u,0x4c535a61u,0x686f767du,0x848b9299u,
    0xa0a7aeb5u,0xbcc3cad1u,0xd8dfe6edu,0xf4fb0209u,0x10171e25u,0x2c333a41u,0x484f565du,0x646b7279u
};

// T-tables
alignas(64) static uint32_t T1_table[4][256];
alignas(64) static uint32_t T2_table[4][256];
static bool tables_inited = false;

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void init_T_tables() {
    if (tables_inited) return;
    for (int pos = 0; pos < 4; ++pos) {
        for (int b = 0; b < 256; ++b) {
            unsigned char sb = Sbox[(b & 0xF0) >> 4][b & 0x0F];
            uint32_t B = ((uint32_t)sb) << (8 * (3 - pos)); // pos=0 -> MSB
            uint32_t C1 = B ^ rotl32(B, 2) ^ rotl32(B, 10) ^ rotl32(B, 18) ^ rotl32(B, 24);
            uint32_t C2 = B ^ rotl32(B, 13) ^ rotl32(B, 23);
            T1_table[pos][b] = C1;
            T2_table[pos][b] = C2;
        }
    }
    tables_inited = true;
}

// setkey
void setkey(uint32_t rk[32], uint32_t MK[4], uint32_t k[36], int mod) {
    init_T_tables();
    k[0] = MK[0] ^ FK[0];
    k[1] = MK[1] ^ FK[1];
    k[2] = MK[2] ^ FK[2];
    k[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
        uint8_t a0 = (tmp >> 24) & 0xFF, a1 = (tmp >> 16) & 0xFF, a2 = (tmp >> 8) & 0xFF, a3 = (tmp) & 0xFF;
        uint32_t t = T2_table[0][a0] ^ T2_table[1][a1] ^ T2_table[2][a2] ^ T2_table[3][a3];
        k[i + 4] = k[i] ^ t;
        rk[i] = k[i + 4];
    }
    if (mod) {
        for (int i = 0; i < 16; i++) {
            uint32_t tmp = rk[i]; rk[i] = rk[31 - i]; rk[31 - i] = tmp;
        }
    }
}

// 单块加密（用 T1 表）
void sm4_encrypt_block_scalar(const unsigned char in[16], unsigned char out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    GET_ULONG_BE(X[0], in, 0); GET_ULONG_BE(X[1], in, 4); GET_ULONG_BE(X[2], in, 8); GET_ULONG_BE(X[3], in, 12);
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
        uint8_t a0 = (tmp >> 24) & 0xFF, a1 = (tmp >> 16) & 0xFF, a2 = (tmp >> 8) & 0xFF, a3 = (tmp) & 0xFF;
        uint32_t t = T1_table[0][a0] ^ T1_table[1][a1] ^ T1_table[2][a2] ^ T1_table[3][a3];
        X[i + 4] = X[i] ^ t;
    }
    PUT_ULONG_BE(X[35], out, 0); PUT_ULONG_BE(X[34], out, 4); PUT_ULONG_BE(X[33], out, 8); PUT_ULONG_BE(X[32], out, 12);
}

//  SIMD合并并行处理
void sm4_encrypt_4blocks_no_gather(const unsigned char in0[16], const unsigned char in1[16], const unsigned char in2[16], const unsigned char in3[16],
    unsigned char out0[16], unsigned char out1[16], unsigned char out2[16], unsigned char out3[16],
    const uint32_t rk[32]) {
    uint32_t X0[36] = { 0 }, X1[36] = { 0 }, X2[36] = { 0 }, X3[36] = { 0 };
    GET_ULONG_BE(X0[0], in0, 0); GET_ULONG_BE(X0[1], in0, 4); GET_ULONG_BE(X0[2], in0, 8); GET_ULONG_BE(X0[3], in0, 12);
    GET_ULONG_BE(X1[0], in1, 0); GET_ULONG_BE(X1[1], in1, 4); GET_ULONG_BE(X1[2], in1, 8); GET_ULONG_BE(X1[3], in1, 12);
    GET_ULONG_BE(X2[0], in2, 0); GET_ULONG_BE(X2[1], in2, 4); GET_ULONG_BE(X2[2], in2, 8); GET_ULONG_BE(X2[3], in2, 12);
    GET_ULONG_BE(X3[0], in3, 0); GET_ULONG_BE(X3[1], in3, 4); GET_ULONG_BE(X3[2], in3, 8); GET_ULONG_BE(X3[3], in3, 12);

    for (int i = 0; i < 32; i++) {
        uint32_t tmp0 = X0[i + 1] ^ X0[i + 2] ^ X0[i + 3] ^ rk[i];
        uint32_t tmp1 = X1[i + 1] ^ X1[i + 2] ^ X1[i + 3] ^ rk[i];
        uint32_t tmp2 = X2[i + 1] ^ X2[i + 2] ^ X2[i + 3] ^ rk[i];
        uint32_t tmp3 = X3[i + 1] ^ X3[i + 2] ^ X3[i + 3] ^ rk[i];

        // table0 (从高到低)
        uint32_t a0 = T1_table[0][(tmp0 >> 24) & 0xFF];
        uint32_t a1 = T1_table[0][(tmp1 >> 24) & 0xFF];
        uint32_t a2 = T1_table[0][(tmp2 >> 24) & 0xFF];
        uint32_t a3 = T1_table[0][(tmp3 >> 24) & 0xFF];
        __m128i r0 = _mm_set_epi32((int)a3, (int)a2, (int)a1, (int)a0);

        // table1
        a0 = T1_table[1][(tmp0 >> 16) & 0xFF];
        a1 = T1_table[1][(tmp1 >> 16) & 0xFF];
        a2 = T1_table[1][(tmp2 >> 16) & 0xFF];
        a3 = T1_table[1][(tmp3 >> 16) & 0xFF];
        __m128i r1 = _mm_set_epi32((int)a3, (int)a2, (int)a1, (int)a0);

        // table2
        a0 = T1_table[2][(tmp0 >> 8) & 0xFF];
        a1 = T1_table[2][(tmp1 >> 8) & 0xFF];
        a2 = T1_table[2][(tmp2 >> 8) & 0xFF];
        a3 = T1_table[2][(tmp3 >> 8) & 0xFF];
        __m128i r2 = _mm_set_epi32((int)a3, (int)a2, (int)a1, (int)a0);

        // table3
        a0 = T1_table[3][(tmp0) & 0xFF];
        a1 = T1_table[3][(tmp1) & 0xFF];
        a2 = T1_table[3][(tmp2) & 0xFF];
        a3 = T1_table[3][(tmp3) & 0xFF];
        __m128i r3 = _mm_set_epi32((int)a3, (int)a2, (int)a1, (int)a0);

        // 合并四个表的结果：res = r0 ^ r1 ^ r2 ^ r3 (每个 lane 对应一个块的 t 值)
        __m128i res = _mm_xor_si128(r0, r1);
        res = _mm_xor_si128(res, r2);
        res = _mm_xor_si128(res, r3);

        // 存到临时数组再取出四个 uint32
        uint32_t tvals[4];
        _mm_storeu_si128((__m128i*)tvals, res); // 在内存只写一次
        X0[i + 4] = X0[i] ^ tvals[0];
        X1[i + 4] = X1[i] ^ tvals[1];
        X2[i + 4] = X2[i] ^ tvals[2];
        X3[i + 4] = X3[i] ^ tvals[3];
    }

    PUT_ULONG_BE(X0[35], out0, 0); PUT_ULONG_BE(X0[34], out0, 4); PUT_ULONG_BE(X0[33], out0, 8); PUT_ULONG_BE(X0[32], out0, 12);
    PUT_ULONG_BE(X1[35], out1, 0); PUT_ULONG_BE(X1[34], out1, 4); PUT_ULONG_BE(X1[33], out1, 8); PUT_ULONG_BE(X1[32], out1, 12);
    PUT_ULONG_BE(X2[35], out2, 0); PUT_ULONG_BE(X2[34], out2, 4); PUT_ULONG_BE(X2[33], out2, 8); PUT_ULONG_BE(X2[32], out2, 12);
    PUT_ULONG_BE(X3[35], out3, 0); PUT_ULONG_BE(X3[34], out3, 4); PUT_ULONG_BE(X3[33], out3, 8); PUT_ULONG_BE(X3[32], out3, 12);
}

// CTR 模式加密（实现并行）
void encrypt_ctr_no_gather(const unsigned char* in, unsigned char* out, size_t len,
    uint32_t MK[4], uint32_t ktmp[36], unsigned char iv[16]) {
    init_T_tables();
    uint32_t rk[32];
    setkey(rk, MK, ktmp, 0);

    size_t offset = 0;
    uint64_t counter_high = ((uint64_t)iv[0] << 56) | ((uint64_t)iv[1] << 48) | ((uint64_t)iv[2] << 40) | ((uint64_t)iv[3] << 32)
        | ((uint64_t)iv[4] << 24) | ((uint64_t)iv[5] << 16) | ((uint64_t)iv[6] << 8) | ((uint64_t)iv[7]);
    uint64_t counter_low = ((uint64_t)iv[8] << 56) | ((uint64_t)iv[9] << 48) | ((uint64_t)iv[10] << 40) | ((uint64_t)iv[11] << 32)
        | ((uint64_t)iv[12] << 24) | ((uint64_t)iv[13] << 16) | ((uint64_t)iv[14] << 8) | ((uint64_t)iv[15]);

    // 并行 4 块为单位
    while (offset + 16 * 4 <= len) {
        __m128i base = _mm_set_epi64x((long long)counter_high, (long long)counter_low);
        __m128i inc0 = base;
        __m128i inc1 = _mm_add_epi64(base, _mm_set_epi64x(0, 1));
        __m128i inc2 = _mm_add_epi64(base, _mm_set_epi64x(0, 2));
        __m128i inc3 = _mm_add_epi64(base, _mm_set_epi64x(0, 3));
        counter_low += 4;

        unsigned char ctr0[16], ctr1[16], ctr2[16], ctr3[16];

        uint64_t inc_vals[4][2];
        _mm_storeu_si128((__m128i*)inc_vals[0], inc0);
        _mm_storeu_si128((__m128i*)inc_vals[1], inc1);
        _mm_storeu_si128((__m128i*)inc_vals[2], inc2);
        _mm_storeu_si128((__m128i*)inc_vals[3], inc3);

        auto store_be128 = [&](unsigned char* dst, uint64_t hi, uint64_t lo) {
            for (int i = 0; i < 8; i++) dst[i] = (unsigned char)((hi >> (56 - 8 * i)) & 0xFF);
            for (int i = 0; i < 8; i++) dst[8 + i] = (unsigned char)((lo >> (56 - 8 * i)) & 0xFF);
        };

        store_be128(ctr0, (uint64_t)inc_vals[0][1], (uint64_t)inc_vals[0][0]);
        store_be128(ctr1, (uint64_t)inc_vals[1][1], (uint64_t)inc_vals[1][0]);
        store_be128(ctr2, (uint64_t)inc_vals[2][1], (uint64_t)inc_vals[2][0]);
        store_be128(ctr3, (uint64_t)inc_vals[3][1], (uint64_t)inc_vals[3][0]);

        unsigned char ke0[16], ke1[16], ke2[16], ke3[16];
        sm4_encrypt_4blocks_no_gather(ctr0, ctr1, ctr2, ctr3, ke0, ke1, ke2, ke3, rk);

        for (int j = 0; j < 16; j++) out[offset + j] = in[offset + j] ^ ke0[j];
        for (int j = 0; j < 16; j++) out[offset + 16 + j] = in[offset + 16 + j] ^ ke1[j];
        for (int j = 0; j < 16; j++) out[offset + 32 + j] = in[offset + 32 + j] ^ ke2[j];
        for (int j = 0; j < 16; j++) out[offset + 48 + j] = in[offset + 48 + j] ^ ke3[j];

        offset += 64;
    }

    
    while (offset + 16 <= len) {
        uint64_t c0 = counter_low++;
        unsigned char ctr[16];
        for (int i = 0; i < 8; i++) ctr[i] = (counter_high >> (56 - 8 * i)) & 0xFF;
        for (int i = 0; i < 8; i++) ctr[8 + i] = (c0 >> (56 - 8 * i)) & 0xFF;
        unsigned char ke[16];
        sm4_encrypt_block_scalar(ctr, ke, rk);
        for (int j = 0; j < 16; j++) out[offset + j] = in[offset + j] ^ ke[j];
        offset += 16;
    }

    if (offset < len) {
        uint64_t c0 = counter_low++;
        unsigned char ctr[16];
        for (int i = 0; i < 8; i++) ctr[i] = (counter_high >> (56 - 8 * i)) & 0xFF;
        for (int i = 0; i < 8; i++) ctr[8 + i] = (c0 >> (56 - 8 * i)) & 0xFF;
        unsigned char ke[16];
        sm4_encrypt_block_scalar(ctr, ke, rk);
        size_t rem = len - offset;
        for (size_t j = 0; j < rem; j++) out[offset + j] = in[offset + j] ^ ke[j];
    }
}

////随机生成明文
char* rand_str_cstyle(int length) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()`~-_=+[{]{|;:'\",<.>/?";
    static const int N = sizeof(chars) - 1;
    random_device rd; mt19937_64 gen(rd()); uniform_int_distribution<int> dist(0, N - 1);
    char* s = new char[length + 1];
    for (int i = 0; i < length; i++) s[i] = chars[dist(gen)];
    s[length] = 0; return s;
}

int main() {
    init_T_tables();

    uint32_t MK[4] = { 0x01234567u, 0x89abcdefu, 0xfedcba98u, 0x76543210u };
    uint32_t key[36] = { 0 };
    unsigned char iv[16] = { 0 }; // initial counter

    size_t length = MAX;
    unsigned char* plaintext = (unsigned char*)aligned_malloc(32, length);
    unsigned char* ciphertext = (unsigned char*)aligned_malloc(32, length);
    unsigned char* decrypted = (unsigned char*)aligned_malloc(32, length);
    if (!plaintext || !ciphertext || !decrypted) {
        cerr << "aligned_malloc failed\n";
        aligned_free(plaintext); aligned_free(ciphertext); aligned_free(decrypted);
        return 1;
    }

    char* src = rand_str_cstyle((int)length);
    memcpy(plaintext, src, length);

    auto s = chrono::high_resolution_clock::now();
    encrypt_ctr_no_gather(plaintext, ciphertext, length, MK, key, iv);
    auto e = chrono::high_resolution_clock::now();
    cout << "CTR加密耗时: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << " us\n";

    memset(iv, 0, 16);
    s = chrono::high_resolution_clock::now();
    encrypt_ctr_no_gather(ciphertext, decrypted, length, MK, key, iv);
    e = chrono::high_resolution_clock::now();
    cout << "CTR解密耗时: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << " us\n";

    if (memcmp(plaintext, decrypted, length) == 0) cout << "Decrypted correct\n";
    else cout << "Mismatch!\n";

    aligned_free(plaintext);
    aligned_free(ciphertext);
    aligned_free(decrypted);
    delete[] src;
    return 0;
}
