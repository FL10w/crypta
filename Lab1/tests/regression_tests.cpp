#include <gtest/gtest.h>

import std;
import crypto.cipher;
import crypto.context;
import crypto.des;
import crypto.deal;
import crypto.modes;
import crypto.padding;

namespace {
std::vector<std::byte> Hex(std::string_view text) {
    std::vector<std::byte> result;
    for (std::size_t i = 0; i < text.size(); i += 2)
        result.push_back(static_cast<std::byte>(std::stoul(std::string(text.substr(i, 2)), nullptr, 16)));
    return result;
}

struct Variant { std::size_t key_size; bool des; };
constexpr std::array variants{Variant{8, true}, Variant{16, false}, Variant{24, false}, Variant{32, false}};

std::unique_ptr<crypto::SymmetricCipher> Cipher(bool des) {
    if (des) return std::make_unique<crypto::DES>();
    return std::make_unique<crypto::DEAL>();
}

std::vector<std::byte> Read(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file || file.tellg() < 0) throw std::runtime_error("read failed");
    std::vector<std::byte> data(static_cast<std::size_t>(file.tellg()));
    file.seekg(0);
    if (!data.empty() && !file.read(reinterpret_cast<char*>(data.data()), data.size()))
        throw std::runtime_error("read failed");
    return data;
}

struct TemporaryFiles {
    std::filesystem::path directory;
    TemporaryFiles() {
        directory = std::filesystem::temp_directory_path() /
            ("crypta-regression-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directory(directory);
    }
    ~TemporaryFiles() {
        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }
};
}

TEST(Regression, EveryContextModeAndPaddingPreservesSupportedBoundaryInputs) {
    for (const auto variant : variants) {
        const auto key = std::vector(variant.key_size, std::byte{0x13});
        const auto iv = std::vector(variant.des ? 8 : 16, std::byte{0x17});
        for (int mode = 0; mode < 7; ++mode) {
            for (int padding = 0; padding < 4; ++padding) {
                crypto::SymmetricCipherContext context(Cipher(variant.des), key,
                    static_cast<crypto::CipherMode>(mode), static_cast<crypto::PaddingMode>(padding),
                    mode == 0 ? std::span<const std::byte>{} : iv);
                for (const auto size : {0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 65}) {
                    if (padding == 0 && size == 0) continue;
                    SCOPED_TRACE(::testing::Message() << "key=" << variant.key_size << " mode=" << mode
                        << " padding=" << padding << " size=" << size);
                    std::vector<std::byte> input(size);
                    for (int i = 0; i < size; ++i) input[i] = static_cast<std::byte>((i * 29 + 11) & 0xFF);
                    if (size) input.back() = std::byte{1};
                    std::vector<std::byte> encrypted, restored;
                    context.EncryptAsync(input, encrypted).get();
                    // Decryption uses a separate context with the same key and IV.
                    crypto::SymmetricCipherContext reader(Cipher(variant.des), key,
                        static_cast<crypto::CipherMode>(mode), static_cast<crypto::PaddingMode>(padding),
                        mode == 0 ? std::span<const std::byte>{} : iv);
                    reader.DecryptAsync(encrypted, restored).get();
                    EXPECT_EQ(restored, input);
                }
            }
        }
    }
}

TEST(Regression, FileOverloadsPreserveSupportedInputsWithoutChangingInput) {
    TemporaryFiles temp;
    const auto input = temp.directory / "input.bin";
    const auto encrypted = temp.directory / "cipher.bin";
    const auto restored = temp.directory / "restored.bin";
    for (const auto variant : variants) {
        const auto key = std::vector(variant.key_size, std::byte{0x13});
        const auto iv = std::vector(variant.des ? 8 : 16, std::byte{0x17});
        for (int mode = 0; mode < 7; ++mode) {
            for (int padding = 0; padding < 4; ++padding) {
                crypto::SymmetricCipherContext context(Cipher(variant.des), key,
                    static_cast<crypto::CipherMode>(mode), static_cast<crypto::PaddingMode>(padding),
                    mode == 0 ? std::span<const std::byte>{} : iv);
                for (const auto size : {0, 32}) {
                    if (padding == 0 && size == 0) continue;
                    SCOPED_TRACE(::testing::Message() << "key=" << variant.key_size << " mode=" << mode
                        << " padding=" << padding << " file_size=" << size);
                    std::vector<std::byte> bytes(size, std::byte{0});
                    if (size) bytes.back() = std::byte{1};
                    { std::ofstream file(input, std::ios::binary);
                      if (size) file.write(reinterpret_cast<const char*>(bytes.data()), size); }
                    context.EncryptAsync(input, encrypted).get();
                    context.DecryptAsync(encrypted, restored).get();
                    EXPECT_EQ(Read(input), bytes);
                    EXPECT_EQ(Read(restored), bytes);
                }
            }
        }
    }
}

TEST(Regression, AsyncOperationSurvivesContextDestruction) {
    const auto input = Hex("01020304000001");
    const auto key = Hex("133457799BBCDFF1");
    std::vector<std::byte> encrypted, restored;
    std::future<void> pending;
    {
        crypto::SymmetricCipherContext context(Cipher(true), key,
            crypto::CipherMode::ECB, crypto::PaddingMode::Zeros);
        pending = context.EncryptAsync(input, encrypted);
    }
    pending.get();
    crypto::SymmetricCipherContext reader(Cipher(true), key,
        crypto::CipherMode::ECB, crypto::PaddingMode::Zeros);
    reader.DecryptAsync(encrypted, restored).get();
    EXPECT_EQ(restored, input);
}

TEST(Regression, ZerosContextUsesRawCiphertextWithoutMetadata) {
    const auto key = Hex("133457799BBCDFF1");
    const auto input = Hex("0102030405060701");
    crypto::DES des;
    des.SetKey(key);
    const auto raw = des.EncryptBlock(input);
    crypto::SymmetricCipherContext reader(Cipher(true), key,
        crypto::CipherMode::ECB, crypto::PaddingMode::Zeros);
    std::vector<std::byte> encrypted, output;
    reader.EncryptAsync(input, encrypted).get();
    EXPECT_EQ(encrypted.size(), input.size());
    EXPECT_EQ(encrypted, raw);
    reader.DecryptAsync(raw, output).get();
    EXPECT_EQ(output, input);
}

// Fixed answers generated independently using Brian Gladman's 1999 DEAL
// implementation (full DES path) outside this project. See DEAL_VECTORS.md.
TEST(Regression, DealMatchesIndependentCiphertextsForAllKeySizes) {
    constexpr std::array<std::array<std::string_view, 2>, 3> expected{{
        {"37C38426079AC9DE02CC32F106F43287", "5E48974D3D5FBF4E7B60354E056AE23D"},
        {"265B0482A5D2181DDEB301210266750E", "298DEC07895324F0190E71CC1CA2D360"},
        {"F0137A90D2268B14614F67C16AA5EC51", "E908089FAE31835497EC7C4628110E5B"}
    }};
    for (int variant = 0; variant < 3; ++variant) {
        for (int pattern = 0; pattern < 2; ++pattern) {
            SCOPED_TRACE(::testing::Message() << "variant=" << variant << " pattern=" << pattern);
            std::vector<std::byte> key(16 + variant * 8), input(16);
            if (pattern) {
                for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::byte>(i);
                for (std::size_t i = 0; i < input.size(); ++i) input[i] = static_cast<std::byte>(i * 17);
            }
            crypto::DEAL deal;
            deal.SetKey(key);
            EXPECT_EQ(deal.EncryptBlock(input), Hex(expected[variant][pattern]));
            EXPECT_EQ(deal.DecryptBlock(Hex(expected[variant][pattern])), input);
        }
    }
}
