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

struct TemporaryFiles {
    std::filesystem::path directory = std::filesystem::temp_directory_path() /
        ("crypta-chunks-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    TemporaryFiles() { std::filesystem::create_directory(directory); }
    ~TemporaryFiles() {
        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }
};

void Write(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    std::ofstream file(path, std::ios::binary);
    if (!bytes.empty()) file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (!file) throw std::runtime_error("test write failed");
}

std::vector<std::byte> Read(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file || file.tellg() < 0) throw std::runtime_error("test read failed");
    std::vector<std::byte> bytes(static_cast<std::size_t>(file.tellg()));
    file.seekg(0);
    if (!bytes.empty() && !file.read(reinterpret_cast<char*>(bytes.data()), bytes.size()))
        throw std::runtime_error("test read failed");
    return bytes;
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

TEST(Context, FileChunksMatchArrayOperationsForEveryModeAndPadding) {
    TemporaryFiles temp;
    const auto input_path = temp.directory / "input.bin";
    const auto encrypted_path = temp.directory / "encrypted.bin";
    const auto restored_path = temp.directory / "restored.bin";
    const auto key = Bytes({1, 2, 3, 4});
    const auto iv = Bytes({0xFF, 0xFF, 0xFF, 0xFD});
    for (int mode = 0; mode < 7; ++mode) {
        for (int padding = 0; padding < 4; ++padding) {
            crypto::SymmetricCipherContext context(MakeCipher(), key,
                static_cast<crypto::CipherMode>(mode), static_cast<crypto::PaddingMode>(padding),
                mode == 0 ? std::span<const std::byte>{} : iv);
            for (const auto size : {65535, 65536, 65537, 131077}) {
                SCOPED_TRACE(::testing::Message() << "mode=" << mode << " padding=" << padding << " size=" << size);
                auto input = GenerateLargeInput(size);
                input[65534] = std::byte{0};
                if (size > 65535) input[65535] = std::byte{0};
                input.back() = std::byte{1};
                Write(input_path, input);
                std::vector<std::byte> array_ciphertext, restored;
                context.EncryptAsync(input, array_ciphertext).get();
                context.EncryptAsync(input_path, encrypted_path).get();
                const auto file_ciphertext = Read(encrypted_path);
                EXPECT_EQ(file_ciphertext.size(), array_ciphertext.size());
                if (padding != static_cast<int>(crypto::PaddingMode::ISO10126))
                    EXPECT_EQ(file_ciphertext, array_ciphertext);
                context.DecryptAsync(file_ciphertext, restored).get();
                EXPECT_EQ(restored, input);
                context.DecryptAsync(encrypted_path, restored_path).get();
                EXPECT_EQ(Read(restored_path), input);
                // A file can also contain ciphertext produced by the array overload.
                Write(encrypted_path, array_ciphertext);
                context.DecryptAsync(encrypted_path, restored_path).get();
                EXPECT_EQ(Read(restored_path), input);
                EXPECT_EQ(Read(input_path), input);
            }
        }
    }
}

TEST(Context, ZerosFilesKeepOneByteAndRemoveSuffixAcrossChunks) {
    TemporaryFiles temp;
    const auto input_path = temp.directory / "input.bin";
    const auto encrypted_path = temp.directory / "encrypted.bin";
    const auto restored_path = temp.directory / "restored.bin";
    const auto key = Bytes({1, 2, 3, 4});
    const auto iv = Bytes({0x10, 0x20, 0x30, 0x41});
    for (int mode = 0; mode < 7; ++mode) {
        crypto::SymmetricCipherContext context(MakeCipher(), key,
            static_cast<crypto::CipherMode>(mode), crypto::PaddingMode::Zeros,
            mode == 0 ? std::span<const std::byte>{} : iv);
        for (const auto size : {1, 4, 65536, 65537, 196613}) {
            for (const bool only_zeros : {true, false}) {
                SCOPED_TRACE(::testing::Message() << "mode=" << mode << " size=" << size << " all_zero=" << only_zeros);
                auto input = std::vector(size, std::byte{0});
                if (!only_zeros) input.front() = std::byte{0x17};
                Write(input_path, input);
                context.EncryptFileAsync(input_path, encrypted_path).get();
                context.DecryptFileAsync(encrypted_path, restored_path).get();
                EXPECT_EQ(Read(restored_path), Bytes({only_zeros ? 0u : 0x17u}));
                EXPECT_EQ(Read(input_path), input);
            }
        }
    }
}

TEST(Context, RandomDeltaFileChunksPreserveExplicitDelta) {
    TemporaryFiles temp;
    auto input = GenerateLargeInput(131077);
    const auto input_path = temp.directory / "input.bin";
    const auto encrypted_path = temp.directory / "encrypted.bin";
    const auto restored_path = temp.directory / "restored.bin";
    Write(input_path, input);
    crypto::SymmetricCipherContext context(MakeCipher(), Bytes({1, 2, 3, 4}),
        crypto::CipherMode::RandomDelta, crypto::PaddingMode::PKCS7,
        Bytes({0xFF, 0xFF, 0xFF, 0xFD}), {Bytes({0x12, 0x35})});
    std::vector<std::byte> expected;
    context.EncryptAsync(input, expected).get();
    context.EncryptAsync(input_path, encrypted_path).get();
    EXPECT_EQ(Read(encrypted_path), expected);
    context.DecryptAsync(encrypted_path, restored_path).get();
    EXPECT_EQ(Read(restored_path), input);
}

TEST(Context, FileDecryptionRejectsEmptyAndUnalignedCiphertext) {
    TemporaryFiles temp;
    const auto input_path = temp.directory / "input.bin";
    const auto output_path = temp.directory / "output.bin";
    crypto::SymmetricCipherContext context(MakeCipher(), Bytes({1, 2, 3, 4}),
        crypto::CipherMode::ECB, crypto::PaddingMode::PKCS7);
    for (const auto size : {0, 1, 65537}) {
        const auto input = std::vector(size, std::byte{0x11});
        Write(input_path, input);
        EXPECT_THROW(context.DecryptAsync(input_path, output_path).get(), std::invalid_argument);
        EXPECT_EQ(Read(input_path), input);
    }
}

TEST(Context, FileOperationRejectsInputAsOutputWithoutTruncatingIt) {
    TemporaryFiles temp;
    const auto input_path = temp.directory / "input.bin";
    const auto alias_path = temp.directory / "alias.bin";
    const auto input = Bytes({1, 2, 3});
    Write(input_path, input);
    std::filesystem::create_hard_link(input_path, alias_path);
    crypto::SymmetricCipherContext context(MakeCipher(), Bytes({1, 2, 3, 4}),
        crypto::CipherMode::ECB, crypto::PaddingMode::PKCS7);
    EXPECT_THROW(context.EncryptAsync(input_path, input_path).get(), std::invalid_argument);
    EXPECT_THROW(context.DecryptAsync(input_path, input_path).get(), std::invalid_argument);
    EXPECT_THROW(context.EncryptAsync(input_path, alias_path).get(), std::invalid_argument);
    EXPECT_EQ(Read(input_path), input);
}
