#include <cstdint>
#include <vector>
#include <array>
#include <iostream>
#include <iomanip>
#include <sstream>
#include<chrono>
namespace sm3 {

    // 循环左移
    static inline uint32_t rotl(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    // 布尔函数
    static inline uint32_t FF(uint32_t a, uint32_t b, uint32_t c, int j) {
        return (j < 16) ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
    }
    static inline uint32_t GG(uint32_t e, uint32_t f, uint32_t g, int j) {
        return (j < 16) ? (e ^ f ^ g) : ((e & f) | ((~e) & g));
    }

    // 置换
    static inline uint32_t P0(uint32_t x) { return x ^ rotl(x, 9) ^ rotl(x, 17); }
    static inline uint32_t P1(uint32_t x) { return x ^ rotl(x, 15) ^ rotl(x, 23); }

    // 常量 Tj
    static inline uint32_t T(int j) {
        return (j < 16) ? 0x79CC4519u : 0x7A879D8Au;
    }

    // 大端读写
    static inline uint32_t load_be32(const uint8_t* p) {
        return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
            (uint32_t)p[2] << 8 | (uint32_t)p[3];
    }
    static inline void store_be32(uint32_t v, uint8_t* p) {
        p[0] = uint8_t(v >> 24);
        p[1] = uint8_t(v >> 16);
        p[2] = uint8_t(v >> 8);
        p[3] = uint8_t(v);
    }

    // 压缩函数 CF, 对单个512-bit分组
    static void compress(std::array<uint32_t, 8>& V, const uint8_t* block) {
        uint32_t W[68];
        uint32_t W1[64];

        for (int i = 0; i < 16; ++i) {
            W[i] = load_be32(block + 4 * i);
        }
        for (int j = 16; j < 68; ++j) {
            uint32_t x = W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15);
            W[j] = P1(x) ^ rotl(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t TJ = T(j);
            uint32_t SS1 = rotl((rotl(A, 12) + E + rotl(TJ, j)) & 0xFFFFFFFFu, 7);
            uint32_t SS2 = SS1 ^ rotl(A, 12);
            uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFFu;
            uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFFu;
            D = C;
            C = rotl(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotl(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    // 计算 SM3 摘要（输入任意字节序列）
    std::array<uint8_t, 32> digest(const std::vector<uint8_t>& msg) {
        // 初始向量
        std::array<uint32_t, 8> V = {
            0x7380166Fu, 0x4914B2B9u, 0x172442D7u, 0xDA8A0600u,
            0xA96F30BCu, 0x163138AAu, 0xE38DEE4Du, 0xB0FB0E4Eu
        };

        // 填充
        std::vector<uint8_t> m = msg;
        uint64_t bit_len = static_cast<uint64_t>(m.size()) * 8ull;

        // 先添加一个 1 比特（即 0x80）
        m.push_back(0x80);
        // 填充 0 直到长度 ≡ 448 (mod 512)
        while ((m.size() % 64) != 56) m.push_back(0x00);

        // 追加 64-bit 大端消息长度
        uint8_t len_be[8];
        for (int i = 0; i < 8; ++i) {
            len_be[7 - i] = static_cast<uint8_t>(bit_len >> (8 * i));
        }
        m.insert(m.end(), len_be, len_be + 8);

        // 逐块压缩
        for (size_t off = 0; off < m.size(); off += 64) {
            compress(V, &m[off]);
        }

        // 输出
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            store_be32(V[i], &out[4 * i]);
        }
        return out;
    }

    // 返回十六进制字符串
    std::string hex(const std::array<uint8_t, 32>& d) {
        std::ostringstream oss;
        for (auto b : d) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return oss.str();
    }

}


int main() {
    using namespace sm3;
    //abc
    auto h1 = digest(std::vector<uint8_t>{'a', 'b', 'c'});
    auto startTP = std::chrono::system_clock::now();
    hex(h1);
    auto endTP = std::chrono::system_clock::now();
    std::cout << "加密所用时间 " << std::chrono::duration_cast<std::chrono::microseconds>(endTP - startTP).count() << "微秒" << std::endl;
    std::cout << "SM3(\"abc\") = " << hex(h1) << "\n";
    

    // 空串
    auto h2 = digest({});
    std::cout << "SM3(\"\")   = " << hex(h2) << "\n";

    // 任意消息
    const char* msg = "hello world";
    auto h3 = digest(std::vector<uint8_t>(msg, msg + std::char_traits<char>::length(msg)));
    std::cout << "SM3(\"" << msg << "\") = " << hex(h3) << "\n";

    return 0;
}
