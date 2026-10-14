#include <gtest/gtest.h>

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

}

TEST(Padding, AddsZerosPaddingToBlockBoundary) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0xEE});

    const auto result = crypto::AddPadding(input, 8, crypto::PaddingMode::Zeros);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x00}));
}

TEST(Padding, DoesNotAddZerosPaddingWhenAlreadyAligned) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD});

    const auto result = crypto::AddPadding(input, 4, crypto::PaddingMode::Zeros);

    EXPECT_EQ(result, input);
}

TEST(Padding, RemovesZerosPaddingFromEnd) {
    const auto input = Bytes({0xAA, 0xBB, 0x00, 0x00});

    const auto result = crypto::RemovePadding(input, 4, crypto::PaddingMode::Zeros);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB}));
}

TEST(Padding, ThrowsOnZeroBlockSizeForZerosPadding) {
    const auto input = Bytes({0xAA});

    EXPECT_THROW(
        static_cast<void>(crypto::AddPadding(input, 0, crypto::PaddingMode::Zeros)),
        std::invalid_argument
    );
}

TEST(Padding, ThrowsWhenZerosPaddedDataSizeIsNotBlockAligned) {
    const auto input = Bytes({0xAA, 0xBB, 0x00});

    EXPECT_THROW(
        static_cast<void>(crypto::RemovePadding(input, 4, crypto::PaddingMode::Zeros)),
        std::invalid_argument
    );
}

TEST(Padding, AddsPkcs7Padding) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0xEE});

    const auto result = crypto::AddPadding(input, 8, crypto::PaddingMode::PKCS7);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03, 0x03, 0x03}));
}

TEST(Padding, AddsFullPkcs7BlockWhenAlreadyAligned) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD});

    const auto result = crypto::AddPadding(input, 4, crypto::PaddingMode::PKCS7);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0x04, 0x04, 0x04, 0x04}));
}

TEST(Padding, RemovesPkcs7Padding) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0x03, 0x03, 0x03});

    const auto result = crypto::RemovePadding(input, 6, crypto::PaddingMode::PKCS7);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC}));
}

TEST(Padding, ThrowsOnInvalidPkcs7PaddingBytes) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0x03, 0x00, 0x03});

    EXPECT_THROW(
        static_cast<void>(crypto::RemovePadding(input, 6, crypto::PaddingMode::PKCS7)),
        std::invalid_argument
    );
}

TEST(Padding, AddsAnsiX923Padding) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0xEE});

    const auto result = crypto::AddPadding(input, 8, crypto::PaddingMode::ANSIX923);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x03}));
}

TEST(Padding, AddsFullAnsiX923BlockWhenAlreadyAligned) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD});

    const auto result = crypto::AddPadding(input, 4, crypto::PaddingMode::ANSIX923);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x04}));
}

TEST(Padding, RemovesAnsiX923Padding) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x03});

    const auto result = crypto::RemovePadding(input, 6, crypto::PaddingMode::ANSIX923);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC}));
}

TEST(Padding, ThrowsOnInvalidAnsiX923PaddingBytes) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0x00, 0xFF, 0x03});

    EXPECT_THROW(
        static_cast<void>(crypto::RemovePadding(input, 6, crypto::PaddingMode::ANSIX923)),
        std::invalid_argument
    );
}

TEST(Padding, AddsIso10126PaddingWithCorrectSizeByte) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD, 0xEE});

    const auto result = crypto::AddPadding(input, 8, crypto::PaddingMode::ISO10126);

    ASSERT_EQ(result.size(), 8);
    EXPECT_TRUE(std::equal(input.begin(), input.end(), result.begin()));
    EXPECT_EQ(result.back(), std::byte{0x03});
}

TEST(Padding, AddsFullIso10126BlockWhenAlreadyAligned) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0xDD});

    const auto result = crypto::AddPadding(input, 4, crypto::PaddingMode::ISO10126);

    ASSERT_EQ(result.size(), 8);
    EXPECT_TRUE(std::equal(input.begin(), input.end(), result.begin()));
    EXPECT_EQ(result.back(), std::byte{0x04});
}

TEST(Padding, RemovesIso10126Padding) {
    const auto input = Bytes({0xAA, 0xBB, 0xCC, 0x17, 0x81, 0x03});

    const auto result = crypto::RemovePadding(input, 6, crypto::PaddingMode::ISO10126);

    EXPECT_EQ(result, Bytes({0xAA, 0xBB, 0xCC}));
}

TEST(Padding, ThrowsOnZeroBlockSize) {
    const auto input = Bytes({0xAA});

    EXPECT_THROW(
        static_cast<void>(crypto::AddPadding(input, 0, crypto::PaddingMode::PKCS7)),
        std::invalid_argument
    );
}

TEST(Padding, ThrowsWhenPaddedDataSizeIsNotBlockAligned) {
    const auto input = Bytes({0xAA, 0xBB, 0x01});

    EXPECT_THROW(
        static_cast<void>(crypto::RemovePadding(input, 4, crypto::PaddingMode::PKCS7)),
        std::invalid_argument
    );
}
