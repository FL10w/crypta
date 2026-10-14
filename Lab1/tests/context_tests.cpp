#include <gtest/gtest.h>

import crypto.cipher;
import crypto.context;
import crypto.modes;
import crypto.padding;
import std;

namespace {

std::vector<std::byte> Bytes(std::initializer_list<unsigned int> values) {
    std::vector<std::byte> result;
    result.reserve(values.size());

    for (const auto value : values) {
        result.push_back(static_cast<std::byte>(value));
    }

    return result;
}

class XorCipher final : public crypto::SymmetricCipher {
public:
    void SetKey(std::span<const std::byte> key) override {
        key_.assign(key.begin(), key.end());
    }

    [[nodiscard]]
    std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const override {
        std::vector<std::byte> result(block.begin(), block.end());

        for (auto& byte : result) {
            byte ^= std::byte{0xAA};
        }

        return result;
    }

    [[nodiscard]]
    std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const override {
        return EncryptBlock(block);
    }

    [[nodiscard]]
    std::size_t BlockSize() const override {
        return 4;
    }

private:
    std::vector<std::byte> key_;
};

std::unique_ptr<crypto::SymmetricCipher> MakeCipher() {
    return std::make_unique<XorCipher>();
}

std::vector<std::byte> GenerateLargeInput(std::size_t size) {
    std::vector<std::byte> input;
    input.reserve(size);

    for (std::size_t i = 0; i < size; ++i) {
        input.push_back(static_cast<std::byte>((i * 29 + 11) & 0xFF));
    }

    return input;
}

}

TEST(Context, EncryptAsyncAndDecryptAsyncRoundTrip) {
    const auto key = Bytes({0x01, 0x02, 0x03, 0x04});
    const auto input = Bytes({0x10, 0x20, 0x30, 0x40, 0x50});

    crypto::SymmetricCipherContext context(
        MakeCipher(),
        key,
        crypto::CipherMode::ECB,
        crypto::PaddingMode::PKCS7
    );

    std::vector<std::byte> encrypted;
    context.EncryptAsync(input, encrypted).get();

    std::vector<std::byte> decrypted;
    context.DecryptAsync(encrypted, decrypted).get();

    EXPECT_EQ(decrypted, input);
}

TEST(Context, EncryptFileAsyncAndDecryptFileAsyncRoundTrip) {
    const auto key = Bytes({0x01, 0x02, 0x03, 0x04});
    const auto input = Bytes({0x41, 0x42, 0x43, 0x44, 0x45});

    const auto base = std::filesystem::temp_directory_path();
    const auto input_path = base / "cryptography_context_input.bin";
    const auto encrypted_path = base / "cryptography_context_encrypted.bin";
    const auto decrypted_path = base / "cryptography_context_decrypted.bin";

    {
        std::ofstream file(input_path, std::ios::binary);
        file.write(
            reinterpret_cast<const char*>(input.data()),
            static_cast<std::streamsize>(input.size())
        );
    }

    crypto::SymmetricCipherContext context(
        MakeCipher(),
        key,
        crypto::CipherMode::ECB,
        crypto::PaddingMode::PKCS7
    );

    context.EncryptFileAsync(input_path, encrypted_path).get();
    context.DecryptFileAsync(encrypted_path, decrypted_path).get();

    std::ifstream file(decrypted_path, std::ios::binary | std::ios::ate);
    ASSERT_TRUE(file);

    const auto size = file.tellg();
    ASSERT_EQ(size, static_cast<std::streamoff>(input.size()));

    std::vector<std::byte> decrypted(static_cast<std::size_t>(size));
    file.seekg(0);
    file.read(
        reinterpret_cast<char*>(decrypted.data()),
        static_cast<std::streamsize>(decrypted.size())
    );

    EXPECT_EQ(decrypted, input);

    std::filesystem::remove(input_path);
    std::filesystem::remove(encrypted_path);
    std::filesystem::remove(decrypted_path);
}

TEST(Context, EncryptAsyncAndDecryptAsyncLargeInputRoundTrip) {
    const auto key = Bytes({0x01, 0x02, 0x03, 0x04});
    const auto iv = Bytes({0x10, 0x20, 0x30, 0x40});
    const auto input = GenerateLargeInput(64 * 1024 + 3);

    crypto::SymmetricCipherContext context(
        MakeCipher(),
        key,
        crypto::CipherMode::CTR,
        crypto::PaddingMode::PKCS7,
        iv
    );

    std::vector<std::byte> encrypted;
    context.EncryptAsync(input, encrypted).get();

    std::vector<std::byte> decrypted;
    context.DecryptAsync(encrypted, decrypted).get();

    EXPECT_EQ(decrypted, input);
}
