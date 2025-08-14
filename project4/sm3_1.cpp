#include <cstdint>
#include <vector>
#include <array>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>

namespace sm3 {

    static inline uint32_t rotl(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }
    static inline uint32_t P0(uint32_t x) { return x ^ rotl(x, 9) ^ rotl(x, 17); }
    static inline uint32_t P1(uint32_t x) { return x ^ rotl(x, 15) ^ rotl(x, 23); }
    static inline uint32_t FF(uint32_t a, uint32_t b, uint32_t c, int j) {
        return (j < 16) ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
    }
    static inline uint32_t GG(uint32_t e, uint32_t f, uint32_t g, int j) {
        return (j < 16) ? (e ^ f ^ g) : ((e & f) | ((~e) & g));
    }
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

    // 预计算 Tj << j
    static uint32_t Tj_rot[64];
    static void init_Tj_rot() {
        for (int j = 0; j < 64; ++j) {
            uint32_t Tj = (j < 16) ? 0x79CC4519u : 0x7A879D8Au;
            Tj_rot[j] = rotl(Tj, j);
        }
    }

    // 压缩函数
    static void compress(std::array<uint32_t, 8>& V, const uint8_t* block) {
        uint32_t W[16];
        for (int i = 0; i < 16; ++i) W[i] = load_be32(block + 4 * i);

        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; ++j) {
            // 消息扩展（只用16个W,节省内存访问）
            if (j >= 16) {
                uint32_t x = W[(j - 16) & 0xF] ^ W[(j - 9) & 0xF] ^ rotl(W[(j - 3) & 0xF], 15);
                uint32_t w_new = P1(x) ^ rotl(W[(j - 13) & 0xF], 7) ^ W[(j - 6) & 0xF];
                W[j & 0xF] = w_new;
            }
            uint32_t Wj = W[j & 0xF];
            uint32_t Wj4 = W[(j + 4) & 0xF];
            uint32_t W1 = Wj ^ Wj4;

            // 压缩运算
            uint32_t SS1 = rotl((rotl(A, 12) + E + Tj_rot[j]) & 0xFFFFFFFFu, 7);
            uint32_t SS2 = SS1 ^ rotl(A, 12);
            uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W1) & 0xFFFFFFFFu;
            uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + Wj) & 0xFFFFFFFFu;

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

    // 摘要计算
    std::array<uint8_t, 32> digest(const std::vector<uint8_t>& msg) {
        static bool Tj_inited = false;
        if (!Tj_inited) { init_Tj_rot(); Tj_inited = true; }

        std::array<uint32_t, 8> V = {
            0x7380166Fu, 0x4914B2B9u, 0x172442D7u, 0xDA8A0600u,
            0xA96F30BCu, 0x163138AAu, 0xE38DEE4Du, 0xB0FB0E4Eu
        };

        std::vector<uint8_t> m = msg;
        uint64_t bit_len = static_cast<uint64_t>(m.size()) * 8ull;
        m.push_back(0x80);
        while ((m.size() % 64) != 56) m.push_back(0x00);
        uint8_t len_be[8];
        for (int i = 0; i < 8; ++i) len_be[7 - i] = static_cast<uint8_t>(bit_len >> (8 * i));
        m.insert(m.end(), len_be, len_be + 8);

        for (size_t off = 0; off < m.size(); off += 64) {
            compress(V, &m[off]);
        }

        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) store_be32(V[i], &out[4 * i]);
        return out;
    }

    std::string hex(const std::array<uint8_t, 32>& d) {
        std::ostringstream oss;
        for (auto b : d) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return oss.str();
    }

} // namespace sm3


int main() {
    using namespace sm3;
    auto h1 = digest(std::vector<uint8_t>{'a', 'b', 'c'});
    auto startTP = std::chrono::system_clock::now();
    hex(h1);
    auto endTP = std::chrono::system_clock::now();
    std::cout << "加密所用时间 " << std::chrono::duration_cast<std::chrono::microseconds>(endTP - startTP).count() << "微秒" << std::endl;
    std::cout << "SM3(\"abc\") = " << hex(h1) << "\n";
    auto h2 = digest({});
    std::cout << "SM3(\"\")   = " << hex(h2) << "\n";
    return 0;
}
