#include <gtest/gtest.h>

import crypto.cipher;
import crypto.feistel;
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

class TestKeyExpansion final : public crypto::KeyExpansion {
public:
    [[nodiscard]]
    std::vector<std::vector<std::byte>> GenerateRoundKeys(
        std::span<const std::byte> key
    ) const override {
        EXPECT_FALSE(key.empty());

        return {
            Bytes({0x01, 0x02}),
            Bytes({0x03, 0x04}),
            Bytes({0x05, 0x06}),
        };
    }
};

class EmptyKeyExpansion final : public crypto::KeyExpansion {
public:
    [[nodiscard]]
    std::vector<std::vector<std::byte>> GenerateRoundKeys(
        std::span<const std::byte>
    ) const override {
        return {};
    }
};

class TestRoundTransformation final : public crypto::RoundTransformation {
public:
    [[nodiscard]]
    std::vector<std::byte> Transform(
        std::span<const std::byte> input_block,
        std::span<const std::byte> round_key
    ) const override {
        std::vector<std::byte> result(input_block.begin(), input_block.end());

        for (std::size_t i = 0; i < result.size(); ++i) {
            result[i] ^= round_key[i % round_key.size()];
        }

        return result;
    }
};

class InvalidSizeRoundTransformation final : public crypto::RoundTransformation {
public:
    [[nodiscard]]
    std::vector<std::byte> Transform(
        std::span<const std::byte>,
        std::span<const std::byte>
    ) const override {
        return Bytes({0x01});
    }
};

std::unique_ptr<const crypto::KeyExpansion> MakeKeyExpansion() {
    return std::make_unique<TestKeyExpansion>();
}

std::unique_ptr<const crypto::RoundTransformation> MakeRoundTransformation() {
    return std::make_unique<TestRoundTransformation>();
}

crypto::FeistelNetwork MakeFeistel(std::size_t block_size = 4) {
    return crypto::FeistelNetwork(
        MakeKeyExpansion(),
        MakeRoundTransformation(),
        block_size
    );
}

}

TEST(FeistelNetwork, ImplementsSymmetricCipherInterface) {
    std::unique_ptr<crypto::SymmetricCipher> cipher = std::make_unique<crypto::FeistelNetwork>(
        MakeKeyExpansion(),
        MakeRoundTransformation(),
        4
    );

    EXPECT_EQ(cipher->BlockSize(), 4);
}

TEST(FeistelNetwork, DecryptsEncryptedBlock) {
    auto feistel = MakeFeistel();
    feistel.SetKey(Bytes({0x10, 0x20, 0x30, 0x40}));

    const auto input = Bytes({0x11, 0x22, 0x33, 0x44});

    const auto encrypted = feistel.EncryptBlock(input);
    const auto decrypted = feistel.DecryptBlock(encrypted);

    EXPECT_NE(encrypted, input);
    EXPECT_EQ(decrypted, input);
}

TEST(FeistelNetwork, RejectsOddBlockSize) {
    EXPECT_THROW(
        static_cast<void>(crypto::FeistelNetwork(
            MakeKeyExpansion(),
            MakeRoundTransformation(),
            3
        )),
        std::invalid_argument
    );
}

TEST(FeistelNetwork, RejectsZeroBlockSize) {
    EXPECT_THROW(
        static_cast<void>(crypto::FeistelNetwork(
            MakeKeyExpansion(),
            MakeRoundTransformation(),
            0
        )),
        std::invalid_argument
    );
}

TEST(FeistelNetwork, RejectsNullKeyExpansion) {
    EXPECT_THROW(
        static_cast<void>(crypto::FeistelNetwork(
            {},
            MakeRoundTransformation(),
            4
        )),
        std::invalid_argument
    );
}

TEST(FeistelNetwork, RejectsNullRoundTransformation) {
    EXPECT_THROW(
        static_cast<void>(crypto::FeistelNetwork(
            MakeKeyExpansion(),
            {},
            4
        )),
        std::invalid_argument
    );
}

TEST(FeistelNetwork, RejectsEncryptionBeforeSetKey) {
    auto feistel = MakeFeistel();

    EXPECT_THROW(
        static_cast<void>(feistel.EncryptBlock(Bytes({0x11, 0x22, 0x33, 0x44}))),
        std::invalid_argument
    );
}

TEST(FeistelNetwork, RejectsInvalidInputBlockSize) {
    auto feistel = MakeFeistel();
    feistel.SetKey(Bytes({0x10, 0x20, 0x30, 0x40}));

    EXPECT_THROW(
        static_cast<void>(feistel.EncryptBlock(Bytes({0x11, 0x22, 0x33}))),
        std::invalid_argument
    );
}

TEST(FeistelNetwork, RejectsEmptyRoundKeys) {
    crypto::FeistelNetwork feistel(
        std::make_unique<EmptyKeyExpansion>(),
        MakeRoundTransformation(),
        4
    );

    EXPECT_THROW(
        feistel.SetKey(Bytes({0x10, 0x20, 0x30, 0x40})),
        std::invalid_argument
    );
}

TEST(FeistelNetwork, RejectsInvalidRoundTransformationSize) {
    crypto::FeistelNetwork feistel(
        MakeKeyExpansion(),
        std::make_unique<InvalidSizeRoundTransformation>(),
        4
    );
    feistel.SetKey(Bytes({0x10, 0x20, 0x30, 0x40}));

    EXPECT_THROW(
        static_cast<void>(feistel.EncryptBlock(Bytes({0x11, 0x22, 0x33, 0x44}))),
        std::invalid_argument
    );
}
