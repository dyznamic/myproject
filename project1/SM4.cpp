#include<iostream>
#include<ctime>
#include<cstdlib>
#include <algorithm>
#include <chrono>
using namespace std;

#define MAX 160000 //最大明文长度

//定义循环左移函数
//循环左移变换
unsigned int leftshift(unsigned int X, unsigned int len)
{
    return (X >> (sizeof(unsigned int) * 8 - len) | (X << len));//按位或
}
//大端转换
#define GET_ULONG_BE(n,b,i) \
		{\
		(n) = ((unsigned long)(b)[(i)]     << 24) \
			| ((unsigned long)(b)[(i) + 1] << 16) \
			| ((unsigned long)(b)[(i) + 2] <<  8) \
			| ((unsigned long)(b)[(i) + 3]      );\
		}


#define PUT_ULONG_BE(n,b,i) \
		{\
		(b)[(i)    ] = (unsigned char) ( (n) >> 24 );\
		(b)[(i) + 1] = (unsigned char) ( (n) >> 16 );\
		(b)[(i) + 2] = (unsigned char) ( (n) >>  8 );\
		(b)[(i) + 3] = (unsigned char) ( (n)       );\
		}





const unsigned char Sbox[16][16] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};
const unsigned int FK[4] = { 0XA3B1BAC6,0X56AA3350,0X677D9197,0XB27022DC };
const unsigned int CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};


//T1
unsigned int T1(unsigned int X)
{
    //按字节划分X
    unsigned char a[4];
    PUT_ULONG_BE(X, a, 0);
    //S盒非线性变换
    unsigned char b3 = Sbox[(a[0] & 0xf0) >> 4][a[0] & 0x0f];
    unsigned char b2 = Sbox[(a[1] & 0xf0) >> 4][a[1] & 0x0f];
    unsigned char b1 = Sbox[(a[2] & 0xf0) >> 4][a[2] & 0x0f];
    unsigned char b0 = Sbox[(a[3] & 0xf0) >> 4][a[3] & 0x0f];
    //循环左移线性变换
    unsigned int B = (b3 << 24) | (b2 << 16) | (b1 << 8) |(b0);
    unsigned int C = B ^ leftshift(B, 2) ^ leftshift(B, 10) ^ leftshift(B, 18) ^ leftshift(B, 24);
    return C;

}
//T2
unsigned int T2(unsigned int X)
{
    //按字节划分X
    unsigned char a[4];
    PUT_ULONG_BE(X, a, 0);
    //S盒非线性变换
    unsigned char b3 = Sbox[(a[0] & 0xf0) >> 4][a[0] & 0x0f];
    unsigned char b2 = Sbox[(a[1] & 0xf0) >> 4][a[1] & 0x0f];
    unsigned char b1 = Sbox[(a[2] & 0xf0) >> 4][a[2] & 0x0f];
    unsigned char b0 = Sbox[(a[3] & 0xf0) >> 4][a[3] & 0x0f];
    //循环左移线性变换
    unsigned int B = (b3 << 24) | (b2 << 16) | (b1 << 8) |(b0);
    unsigned int C = B ^ leftshift(B, 13) ^ leftshift(B, 23);
    return C;

}
//轮密钥扩展
void setkey(unsigned int rk[32], unsigned int MK[4], unsigned int k[36],int mod)
{
    k[0] = MK[0] ^ FK[0];
    k[1] = MK[1] ^ FK[1];
    k[2] = MK[2] ^ FK[2];
    k[3] = MK[3] ^ FK[3];
    //加密
    for (int i = 0; i < 32; i++)
    {
        k[i + 4] = k[i] ^ T2(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        rk[i] = k[i + 4];

    }
    //解密
    if (mod)
    {
        for (int i = 0; i < 16; ++i)
        {
            int temp = rk[i];
            rk[i] = rk[31 - i];
            rk[31 - i] = temp;
        }
    }
}
void round(unsigned int sk[32], const unsigned char input[16], unsigned char output[16])
{
    unsigned int X[36] = { 0x0 };
    GET_ULONG_BE(X[0], input, 0);
    GET_ULONG_BE(X[1], input, 4);
    GET_ULONG_BE(X[2], input, 8);
    GET_ULONG_BE(X[3], input, 12);
    for (int i = 0; i < 32; i++)
    {
        X[i + 4] = X[i] ^ T1(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ sk[i]);
    }
    PUT_ULONG_BE(X[35], output, 0);
    PUT_ULONG_BE(X[34], output, 4);
    PUT_ULONG_BE(X[33], output, 8);
    PUT_ULONG_BE(X[32], output, 12);
}
//加密函数(cbc模式，轮密钥生成，iv输入，明文输入，初始密钥输入)
//padding填充(len不被16整除时填充余数)
void encode(const unsigned char* src, unsigned char* dst, unsigned int MK[4],unsigned int k[36], unsigned char iv[16],size_t& len)
{
    size_t i;
    unsigned int sk[32];
    setkey(sk, MK, k, 0);
    i = 16 - (len % 16);
    char* padding = nullptr;
    if (i > 0)
    {
        padding = new char[len + i];
        memset(padding, i, len + i);
        memcpy(padding, src, len);
        src = (unsigned char*)padding;

    }
    len += i;
    i = len;
    while (i > 0)
    {
        for (int n = 0; n < 16; n++)
        {
            dst[n] = src[n] ^ iv[n];
        }
        round(sk,dst,dst );
        memcpy(iv, dst, 16);
        src += 16;
        dst += 16;
        i -= 16;
    }
    delete[] padding;
}

void decode(const unsigned char* src, unsigned char* dst, unsigned int MK[4],unsigned int k[36], unsigned char iv[16], size_t&len)
{
    unsigned int sk[32];
    unsigned char temp[16];
    setkey(sk, MK, k, 1);
    unsigned char* fst = dst;
    size_t i = len;
    while (i > 0)
    {
        memcpy(temp, src, 16);
        round(sk, src, dst);
        for (int n = 0; n < 16; n++)
        {
            dst[n] = dst[n] ^ iv[n];
        }
        memcpy(iv, temp, 16);
        src += 16;
        dst += 16;
        i -= 16;
    }
    //查看是否填充
    i = fst[len - 1];
    if (i >= 1 && i <= 16)
    {
        memset(fst + len - i, 0, i);
        len -= i;
    }
}
#include <random>
char* rand_str_cstyle(int length) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()`~-_=+[{]{|;:'\",<.>/?";
    std::random_device rd;
    std::mt19937 generator(rd());

    char* output = new char[length + 1];  // +1 给 '\0' 预留空间
    int index = 0;

    while (index < length) {
        auto randNumb = generator();
        while (randNumb > 93 && index < length) {
            output[index++] = chars[randNumb % 93];
            randNumb /= 93;
        }
    }
    output[length] = '\0';  // 确保 C 风格字符串以 '\0' 结尾
    return output;
}

int main()
{
   
    unsigned int MK[4] = { 0x01234567, 0x89abcdef,0xfedcba98,0x76543210 };
    unsigned int key[36] = { 0x0};
    unsigned char iv[16] = { 0 };
    
    size_t length = MAX;//明文长度
    unsigned char* ciphertext = new unsigned char[MAX];
    unsigned char* plaintext = new unsigned char[MAX];
    //随机生成明文
    char* rand_str = rand_str_cstyle(MAX);
    size_t m_len = length;//记录明文加密后密文长度
    
    //记录加密相同长度明文所用时间(效率

    auto startTP = std::chrono::system_clock::now();
    encode((unsigned char*)rand_str, ciphertext,MK, key, iv, m_len);
    auto endTP = std::chrono::system_clock::now();
    std::cout << "加密所用时间 " << std::chrono::duration_cast<std::chrono::microseconds>(endTP - startTP).count() <<"微秒"<< std::endl;

    /*printf("明文:%d,%s\n加密结果:%d,", length, rand_str, (int)m_len);
    for (int i = 0; i < m_len; i++)
    {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");*/
    
    size_t text_len = m_len;
    memset(iv, 0, sizeof(iv));
  
    auto startTP2 = std::chrono::system_clock::now();
    decode(ciphertext, plaintext,MK,key, iv, text_len);
    auto endTP2 = std::chrono::system_clock::now();
    std::cout << "解密所用时间: " << std::chrono::duration_cast<std::chrono::microseconds>(endTP2 - startTP2).count() <<"微秒"<< std::endl;
    
    plaintext[text_len] = '\0';
    //printf("解密结果:%d,%s", (int)text_len, plaintext);
   
    delete[] rand_str, ciphertext, plaintext;
    return 0;
  
}