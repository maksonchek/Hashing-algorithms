#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>

std::string toHex(uint8_t value) {
    static const char hexDigits[] = "0123456789abcdef";
    std::string hexString;
    hexString += hexDigits[value >> 4];
    hexString += hexDigits[value & 0x0f];
    return hexString;
}

uint32_t leftRotate(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

// Значения для сдвигов (s) и констант (k)
const int s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

const uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};


std::string computeHash(const std::string& message) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;

    // Предварительная обработка сообщения
    std::string paddedMessage = message;
    paddedMessage += '\x80';
    size_t messageSize = message.size();
    while ((paddedMessage.size() % 64) != 56) {
        paddedMessage += '\x00';
    }
    for (size_t i = 0; i < 8; ++i) {
        paddedMessage += static_cast<char>((messageSize << (8 * i)) & 0xFF);
    }

    // Разделение предварительно обработанного сообщения на блоки
    const uint32_t* blocks = reinterpret_cast<const uint32_t*>(paddedMessage.data());
    size_t numBlocks = paddedMessage.size() / 64;

    // Функции
    auto F = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
    auto G = [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); };
    auto H = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
    auto I = [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); };

    // Раунды обновления хеш-значения
    for (size_t i = 0; i < numBlocks; ++i) {
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        const uint32_t* block = blocks + i * 16;

        for (size_t j = 0; j < 64; ++j) {
            uint32_t f, g;
            if (j < 16) {
                f = F(b, c, d);
                g = j;
            }
            else if (j < 32) {
                f = G(b, c, d);
                g = (5 * j + 1) % 16;
            }
            else if (j < 48) {
                f = H(b, c, d);
                g = (3 * j + 5) % 16;
            }
            else {
                f = I(b, c, d);
                g = (7 * j) % 16;
            }

            uint32_t temp = d;
            d = c;
            c = b;
            b += leftRotate((a + f + block[g] + k[j]), s[j]);
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    // Формирование хеш-значения
    std::string hash;
    hash += toHex(h0 >> 24);
    hash += toHex((h0 >> 16) & 0xFF);
    hash += toHex((h0 >> 8) & 0xFF);
    hash += toHex(h0 & 0xFF);
    hash += toHex(h1 >> 24);
    hash += toHex((h1 >> 16) & 0xFF);
    hash += toHex((h1 >> 8) & 0xFF);
    hash += toHex(h1 & 0xFF);
    hash += toHex(h2 >> 24);
    hash += toHex((h2 >> 16) & 0xFF);
    hash += toHex((h2 >> 8) & 0xFF);
    hash += toHex(h2 & 0xFF);
    hash += toHex(h3 >> 24);
    hash += toHex((h3 >> 16) & 0xFF);
    hash += toHex((h3 >> 8) & 0xFF);
    hash += toHex(h3 & 0xFF);

    return hash;
}

int main() {
    setlocale(LC_ALL, "Russian");
    std::string message;

    while (true) {
        std::cout << "Введите сообщение (для выхода введите 'exit'): ";
        std::getline(std::cin, message);

        if (message == "exit") {
            break;
        }

        std::string hash = computeHash(message);
        std::cout << "Хеш-значение: " << hash << std::endl;
    }

    return 0;
}