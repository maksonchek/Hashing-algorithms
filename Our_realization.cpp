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

constexpr uint32_t ROTLEFT(uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (32 - shift));
}

const uint32_t K[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

std::string sha256(const std::string& message) {
    // Constants for SHA-256
    const uint32_t K[] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };

    // Initialize hash values
    uint32_t H[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    // Pre-processing
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

    // Process the message in successive 512-bit chunks
    for (size_t chunkStart = 0; chunkStart < paddedMessage.length(); chunkStart += 64) {
        uint32_t W[64] = { 0 };

        // Prepare the message schedule
        for (int i = 0; i < 16; ++i) {
            W[i] = static_cast<uint32_t>(paddedMessage[chunkStart + i * 4]) << 24 |
                static_cast<uint32_t>(paddedMessage[chunkStart + i * 4 + 1]) << 16 |
                static_cast<uint32_t>(paddedMessage[chunkStart + i * 4 + 2]) << 8 |
                static_cast<uint32_t>(paddedMessage[chunkStart + i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
        }

        // Initialize working variables
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        // Compression function main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
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

        // Add the compressed chunk to the current hash value
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // Produce the final hash value
    std::ostringstream oss;
    for (int i = 0; i < 8; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(8) << H[i];
    }

    return oss.str();
}

std::string md5(const std::string& message) {
    // Padding
    const uint64_t messageLengthBits = message.length() * 8;
    std::string paddedMessage = message;
    paddedMessage += static_cast<char>(0x80);
    while ((paddedMessage.length() * 8) % 512 != 448) {
        paddedMessage += static_cast<char>(0x00);
    }
    paddedMessage += std::string(8, '\0');
    for (int i = 0; i < 8; ++i) {
        paddedMessage[paddedMessage.length() - 8 + i] = static_cast<char>((messageLengthBits >> (56 - i * 8)) & 0xFF);
    }

    // Initialize MD5 state
    uint32_t A = 0x67452301;
    uint32_t B = 0xEFCDAB89;
    uint32_t C = 0x98BADCFE;
    uint32_t D = 0x10325476;

    // Process message in 16-word blocks
    for (size_t i = 0; i < paddedMessage.length(); i += 64) {
        uint32_t M[16];
        for (int j = 0; j < 16; ++j) {
            M[j] = static_cast<uint32_t>(paddedMessage[i + j * 4]) |
                static_cast<uint32_t>(paddedMessage[i + j * 4 + 1]) << 8 |
                static_cast<uint32_t>(paddedMessage[i + j * 4 + 2]) << 16 |
                static_cast<uint32_t>(paddedMessage[i + j * 4 + 3]) << 24;
        }

        uint32_t AA = A;
        uint32_t BB = B;
        uint32_t CC = C;
        uint32_t DD = D;

        // Round 1
        const uint32_t s[] = { 7, 12, 17, 22 };
        for (int j = 0; j < 16; ++j) {
            uint32_t F = (B & C) | ((~B) & D);
            uint32_t g = j;
            uint32_t temp = D;
            D = C;
            C = B;
            B = B + ROTLEFT((A + F + K[j] + M[g]), s[j % 4]);
            A = temp;
        }

        // Round 2
        const uint32_t s2[] = { 5, 9, 14, 20 };
        for (int j = 16; j < 32; ++j) {
            uint32_t F = (D & B) | ((~D) & C);
            uint32_t g = (5 * j + 1) % 16;
            uint32_t temp = D;
            D = C;
            C = B;
            B = B + ROTLEFT((A + F + K[j] + M[g]), s2[j % 4]);
            A = temp;
        }

        // Round 3
        const uint32_t s3[] = { 4, 11, 16, 23 };
        for (int j = 32; j < 48; ++j) {
            uint32_t F = B ^ C ^ D;
            uint32_t g = (3 * j + 5) % 16;
            uint32_t temp = D;
            D = C;
            C = B;
            B = B + ROTLEFT((A + F + K[j] + M[g]), s3[j % 4]);
            A = temp;
        }

        // Round 4
        const uint32_t s4[] = { 6, 10, 15, 21 };
        for (int j = 48; j < 64; ++j) {
            uint32_t F = C ^ (B | (~D));
            uint32_t g = (7 * j) % 16;
            uint32_t temp = D;
            D = C;
            C = B;
            B = B + ROTLEFT((A + F + K[j] + M[g]), s4[j % 4]);
            A = temp;
        }

        A += AA;
        B += BB;
        C += CC;
        D += DD;
    }

    // Output MD5 hash
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << A;
    oss << std::setw(8) << B;
    oss << std::setw(8) << C;
    oss << std::setw(8) << D;

    return oss.str();
}

std::string bpmHash(const std::string& message) {
    std::string sha256Hash = sha256(message);
    std::string md5Hash = md5(message);

    return sha256Hash + md5Hash;
}

int main() {
    bool running = true;
    while (running) {
        std::cout << "Enter a message to hash (or 'exit' to quit): ";
        std::string message;
        std::getline(std::cin, message);

        if (message == "exit") {
            running = false;
        }
        else {
            std::string hash = bpmHash(message);
            std::cout << "Message: " << message << std::endl;
            std::cout << "Hash: " << hash << std::endl;
        }
    }

    return 0;
}