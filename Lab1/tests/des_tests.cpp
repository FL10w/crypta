#include <gtest/gtest.h>

import crypto.cipher;
import crypto.context;
import crypto.des;
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

std::vector<std::byte> GenerateInput(std::size_t size) {
    std::vector<std::byte> result;
    result.reserve(size);

    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(static_cast<std::byte>((i * 37 + 19) & 0xFF));
    }

    return result;
}

std::vector<std::byte> NistKey() {
    return Bytes({
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1
    });
}

std::vector<std::byte> NistPlaintext() {
    return Bytes({
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    });
}

std::vector<std::byte> NistCiphertext() {
    return Bytes({
        0x85, 0xE8, 0x13, 0x54,
        0x0F, 0x0A, 0xB4, 0x05
    });
}

}

TEST(DES, HasEightByteBlockSize) {
    crypto::DES des;

    EXPECT_EQ(des.BlockSize(), 8);
}

TEST(DES, ImplementsSymmetricCipherInterface) {
    std::unique_ptr<crypto::SymmetricCipher> cipher = std::make_unique<crypto::DES>();

    EXPECT_EQ(cipher->BlockSize(), 8);
}

TEST(DES, EncryptsKnownNistVector) {
    crypto::DES des;
    des.SetKey(NistKey());

    EXPECT_EQ(des.EncryptBlock(NistPlaintext()), NistCiphertext());
}

TEST(DES, DecryptsKnownNistVector) {
    crypto::DES des;
    des.SetKey(NistKey());

    EXPECT_EQ(des.DecryptBlock(NistCiphertext()), NistPlaintext());
}

TEST(DES, EncryptsAllZeroVector) {
    crypto::DES des;
    des.SetKey(Bytes({
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    }));

    const auto plaintext = Bytes({
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    });

    const auto expected = Bytes({
        0x8C, 0xA6, 0x4D, 0xE9,
        0xC1, 0xB1, 0x23, 0xA7
    });

    EXPECT_EQ(des.EncryptBlock(plaintext), expected);
}

TEST(DES, DecryptsAllZeroVector) {
    crypto::DES des;
    des.SetKey(Bytes({
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    }));

    const auto ciphertext = Bytes({
        0x8C, 0xA6, 0x4D, 0xE9,
        0xC1, 0xB1, 0x23, 0xA7
    });

    const auto expected = Bytes({
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    });

    EXPECT_EQ(des.DecryptBlock(ciphertext), expected);
}

TEST(DES, RoundTripSingleBlock) {
    crypto::DES des;
    des.SetKey(NistKey());

    const auto input = Bytes({
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0xFE
    });

    const auto encrypted = des.EncryptBlock(input);
    const auto decrypted = des.DecryptBlock(encrypted);

    EXPECT_NE(encrypted, input);
    EXPECT_EQ(decrypted, input);
}

TEST(DES, DifferentKeysProduceDifferentCiphertexts) {
    crypto::DES first;
    first.SetKey(NistKey());

    crypto::DES second;
    second.SetKey(Bytes({
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    }));

    EXPECT_NE(first.EncryptBlock(NistPlaintext()), second.EncryptBlock(NistPlaintext()));
}

TEST(DES, RejectsShortKey) {
    crypto::DES des;

    EXPECT_THROW(
        des.SetKey(Bytes({0x01, 0x02, 0x03, 0x04})),
        std::invalid_argument
    );
}

TEST(DES, RejectsLongKey) {
    crypto::DES des;

    EXPECT_THROW(
        des.SetKey(Bytes({
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09
        })),
        std::invalid_argument
    );
}

TEST(DES, RejectsShortBlockOnEncrypt) {
    crypto::DES des;
    des.SetKey(NistKey());

    EXPECT_THROW(
        static_cast<void>(des.EncryptBlock(Bytes({0x01, 0x02, 0x03}))),
        std::invalid_argument
    );
}

TEST(DES, RejectsLongBlockOnEncrypt) {
    crypto::DES des;
    des.SetKey(NistKey());

    EXPECT_THROW(
        static_cast<void>(des.EncryptBlock(Bytes({
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09
        }))),
        std::invalid_argument
    );
}

TEST(DES, RejectsShortBlockOnDecrypt) {
    crypto::DES des;
    des.SetKey(NistKey());

    EXPECT_THROW(
        static_cast<void>(des.DecryptBlock(Bytes({0x01, 0x02, 0x03}))),
        std::invalid_argument
    );
}

TEST(DES, RejectsEncryptBeforeSetKey) {
    crypto::DES des;

    EXPECT_THROW(
        static_cast<void>(des.EncryptBlock(NistPlaintext())),
        std::invalid_argument
    );
}

TEST(DES, CbcContextRoundTrip) {
    const auto key = NistKey();
    const auto iv = Bytes({
        0xA1, 0xB2, 0xC3, 0xD4,
        0xE5, 0xF6, 0x07, 0x18
    });
    const auto input = GenerateInput(257);

    crypto::SymmetricCipherContext context(
        std::make_unique<crypto::DES>(),
        key,
        crypto::CipherMode::CBC,
        crypto::PaddingMode::PKCS7,
        iv
    );

    std::vector<std::byte> encrypted;
    context.EncryptAsync(input, encrypted).get();

    std::vector<std::byte> decrypted;
    context.DecryptAsync(encrypted, decrypted).get();

    EXPECT_EQ(decrypted, input);
}

TEST(DES, CtrContextLargeInputRoundTrip) {
    const auto key = NistKey();
    const auto iv = Bytes({
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    });
    const auto input = GenerateInput(16 * 1024 + 5);

    crypto::SymmetricCipherContext context(
        std::make_unique<crypto::DES>(),
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
