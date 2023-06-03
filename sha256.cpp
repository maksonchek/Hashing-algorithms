#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

constexpr uint32_t ROTRIGHT(uint32_t value, uint32_t shift) {
    return (value >> shift) | (value << (32 - shift));
}

constexpr uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

constexpr uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr uint32_t EP0(uint32_t x) {
    return ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22);
}

constexpr uint32_t EP1(uint32_t x) {
    return ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25);
}

constexpr uint32_t SIG0(uint32_t x) {
    return ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ (x >> 3);
}

constexpr uint32_t SIG1(uint32_t x) {
    return ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ (x >> 10);
}

std::string sha256(const std::string& message) {
    // Инициализация хеш-значений
    uint32_t h0 = 0x6A09E667;
    uint32_t h1 = 0xBB67AE85;
    uint32_t h2 = 0x3C6EF372;
    uint32_t h3 = 0xA54FF53A;
    uint32_t h4 = 0x510E527F;
    uint32_t h5 = 0x9B05688C;
    uint32_t h6 = 0x1F83D9AB;
    uint32_t h7 = 0x5BE0CD19;

    // Предварительная обработка сообщения
    std::string paddedMessage = message;
    paddedMessage += static_cast<char>(0x80);
    while ((paddedMessage.length() * 8) % 512 != 448) {
        paddedMessage += static_cast<char>(0x00);
    }
    uint64_t messageLengthBits = message.length() * 8;
    paddedMessage += std::string(8, '\0');
    for (int i = 0; i < 8; ++i) {
        paddedMessage[paddedMessage.length() - 8 + i] = static_cast<char>((messageLengthBits >> (56 - i * 8)) & 0xFF);
    }

    // Обработка блоков сообщения
    for (size_t i = 0; i < paddedMessage.length(); i += 64) {
        uint32_t chunk[64] = { 0 };

        for (int j = 0; j < 16; ++j) {
            chunk[j] = static_cast<uint32_t>(paddedMessage[i + j * 4]) << 24 |
                static_cast<uint32_t>(paddedMessage[i + j * 4 + 1]) << 16 |
                static_cast<uint32_t>(paddedMessage[i + j * 4 + 2]) << 8 |
                static_cast<uint32_t>(paddedMessage[i + j * 4 + 3]);
        }

        for (int j = 16; j < 64; ++j) {
            chunk[j] = SIG1(chunk[j - 2]) + chunk[j - 7] + SIG0(chunk[j - 15]) + chunk[j - 16];
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int j = 0; j < 64; ++j) {
            uint32_t temp1 = h + EP1(e) + CH(e, f, g) + 0x428A2F98 + chunk[j];
            uint32_t temp2 = EP0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Формирование хеш-значения в шестнадцатеричной строке
    std::ostringstream oss;
    for (const uint32_t& h : { h0, h1, h2, h3, h4, h5, h6, h7 }) {
        oss << std::hex << std::setfill('0') << std::setw(8) << h;
    }

    return oss.str();
}

int main() {
    setlocale(LC_ALL, "Russian");
    std::string message;
    while (true) {
        std::cout << "Введите сообщение (или 'exit' для выхода): ";
        std::getline(std::cin, message);

        if (message == "exit") {
            break;
        }

        std::string hash = sha256(message);
        std::cout << "SHA-256 хеш: " << hash << std::endl;
    }

    return 0;
}