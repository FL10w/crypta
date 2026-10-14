#include <gtest/gtest.h>

import crypto.cipher;
import crypto.context;
import crypto.deal;
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

std::vector<std::byte> DealKey() {
    return Bytes({
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1,
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    });
}

std::vector<std::byte> DealBlock() {
    return Bytes({
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF
    });
}

std::vector<std::byte> DifferentDealKey() {
    return Bytes({
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10
    });
}

std::vector<std::byte> DealIv() {
    return Bytes({
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0xFE,
        0xEF, 0xCD, 0xAB, 0x89,
        0x67, 0x45, 0x23, 0x01
    });
}

std::vector<std::byte> GenerateInput(std::size_t size) {
    std::vector<std::byte> result;
    result.reserve(size);

    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(static_cast<std::byte>((i * 41 + 23) & 0xFF));
    }

    return result;
}

}

TEST(DEAL, HasSixteenByteBlockSize) {
    crypto::DEAL deal;

    EXPECT_EQ(deal.BlockSize(), 16);
}

TEST(DEAL, ImplementsSymmetricCipherInterface) {
    std::unique_ptr<crypto::SymmetricCipher> cipher = std::make_unique<crypto::DEAL>();

    EXPECT_EQ(cipher->BlockSize(), 16);
}

TEST(DEALKeyExpansion, AcceptsSixteenByteKey) {
    crypto::DEAL deal;

    EXPECT_NO_THROW(deal.SetKey(DealKey()));
}

TEST(DEALKeyExpansion, RejectsShortKey) {
    crypto::DEAL deal;

    EXPECT_THROW(
        deal.SetKey(Bytes({
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1
        })),
        std::invalid_argument
    );
}

TEST(DEALKeyExpansion, RejectsLongKey) {
    crypto::DEAL deal;

    EXPECT_THROW(
        deal.SetKey(Bytes({
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0x42
        })),
        std::invalid_argument
    );
}

TEST(DEALKeyExpansion, GeneratedRoundKeysAllowEncryption) {
    crypto::DEAL deal;
    deal.SetKey(DealKey());

    EXPECT_NO_THROW(static_cast<void>(deal.EncryptBlock(DealBlock())));
}

TEST(DEALKeyExpansion, GeneratedRoundKeysAllowRoundTrip) {
    crypto::DEAL deal;
    deal.SetKey(DealKey());

    const auto input = DealBlock();
    const auto encrypted = deal.EncryptBlock(input);
    const auto decrypted = deal.DecryptBlock(encrypted);

    EXPECT_NE(encrypted, input);
    EXPECT_EQ(decrypted, input);
}

TEST(DEALKeyExpansion, SameKeyProducesStableCiphertext) {
    crypto::DEAL first;
    first.SetKey(DealKey());

    crypto::DEAL second;
    second.SetKey(DealKey());

    EXPECT_EQ(first.EncryptBlock(DealBlock()), second.EncryptBlock(DealBlock()));
}

TEST(DEAL, RejectsShortBlockOnEncrypt) {
    crypto::DEAL deal;
    deal.SetKey(DealKey());

    EXPECT_THROW(
        static_cast<void>(deal.EncryptBlock(Bytes({
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77
        }))),
        std::invalid_argument
    );
}

TEST(DEAL, RejectsLongBlockOnEncrypt) {
    crypto::DEAL deal;
    deal.SetKey(DealKey());

    EXPECT_THROW(
        static_cast<void>(deal.EncryptBlock(Bytes({
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
            0x42
        }))),
        std::invalid_argument
    );
}

TEST(DEAL, RejectsShortBlockOnDecrypt) {
    crypto::DEAL deal;
    deal.SetKey(DealKey());

    EXPECT_THROW(
        static_cast<void>(deal.DecryptBlock(Bytes({
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77
        }))),
        std::invalid_argument
    );
}

TEST(DEAL, RejectsLongBlockOnDecrypt) {
    crypto::DEAL deal;
    deal.SetKey(DealKey());

    EXPECT_THROW(
        static_cast<void>(deal.DecryptBlock(Bytes({
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
            0x42
        }))),
        std::invalid_argument
    );
}

TEST(DEAL, RejectsEncryptBeforeSetKey) {
    crypto::DEAL deal;

    EXPECT_THROW(
        static_cast<void>(deal.EncryptBlock(DealBlock())),
        std::invalid_argument
    );
}

TEST(DEAL, RejectsDecryptBeforeSetKey) {
    crypto::DEAL deal;

    EXPECT_THROW(
        static_cast<void>(deal.DecryptBlock(DealBlock())),
        std::invalid_argument
    );
}

TEST(DEAL, RoundTripSingleBlock) {
    crypto::DEAL deal;
    deal.SetKey(DealKey());

    const auto input = DealBlock();
    const auto encrypted = deal.EncryptBlock(input);
    const auto decrypted = deal.DecryptBlock(encrypted);

    EXPECT_NE(encrypted, input);
    EXPECT_EQ(decrypted, input);
}

TEST(DEAL, DifferentKeysProduceDifferentCiphertexts) {
    crypto::DEAL first;
    first.SetKey(DealKey());

    crypto::DEAL second;
    second.SetKey(DifferentDealKey());

    EXPECT_NE(first.EncryptBlock(DealBlock()), second.EncryptBlock(DealBlock()));
}

TEST(DEAL, EcbContextRoundTrip) {
    const auto input = GenerateInput(257);

    crypto::SymmetricCipherContext context(
        std::make_unique<crypto::DEAL>(),
        DealKey(),
        crypto::CipherMode::ECB,
        crypto::PaddingMode::PKCS7
    );

    std::vector<std::byte> encrypted;
    context.EncryptAsync(input, encrypted).get();

    std::vector<std::byte> decrypted;
    context.DecryptAsync(encrypted, decrypted).get();

    EXPECT_EQ(decrypted, input);
}

TEST(DEAL, CbcContextRoundTrip) {
    const auto input = GenerateInput(257);

    crypto::SymmetricCipherContext context(
        std::make_unique<crypto::DEAL>(),
        DealKey(),
        crypto::CipherMode::CBC,
        crypto::PaddingMode::PKCS7,
        DealIv()
    );

    std::vector<std::byte> encrypted;
    context.EncryptAsync(input, encrypted).get();

    std::vector<std::byte> decrypted;
    context.DecryptAsync(encrypted, decrypted).get();

    EXPECT_EQ(decrypted, input);
}

TEST(DEAL, CtrContextLargeInputRoundTrip) {
    const auto input = GenerateInput(16 * 1024 + 9);

    crypto::SymmetricCipherContext context(
        std::make_unique<crypto::DEAL>(),
        DealKey(),
        crypto::CipherMode::CTR,
        crypto::PaddingMode::PKCS7,
        DealIv()
    );

    std::vector<std::byte> encrypted;
    context.EncryptAsync(input, encrypted).get();

    std::vector<std::byte> decrypted;
    context.DecryptAsync(encrypted, decrypted).get();

    EXPECT_EQ(decrypted, input);
}

TEST(DEAL, RandomDeltaContextRoundTrip) {
    const auto input = GenerateInput(513);

    crypto::SymmetricCipherContext context(
        std::make_unique<crypto::DEAL>(),
        DealKey(),
        crypto::CipherMode::RandomDelta,
        crypto::PaddingMode::PKCS7,
        DealIv()
    );

    std::vector<std::byte> encrypted;
    context.EncryptAsync(input, encrypted).get();

    std::vector<std::byte> decrypted;
    context.DecryptAsync(encrypted, decrypted).get();

    EXPECT_EQ(decrypted, input);
}
