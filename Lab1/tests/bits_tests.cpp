#include <gtest/gtest.h>

import crypto.bits;
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

TEST(PermuteBits, KeepsMsbOrderedBitsWithZeroBasedIndexing) {
    const auto input = Bytes({0b1010'0000});
    const std::vector<std::size_t> p_block{0, 1, 2, 3};

    const auto result = crypto::PermuteBits(
        input,
        p_block,
        crypto::BitOrder::MsbFirst,
        crypto::IndexBase::Zero
    );

    EXPECT_EQ(result, Bytes({0b1010'0000}));
}

TEST(PermuteBits, KeepsLsbOrderedBitsWithZeroBasedIndexing) {
    const auto input = Bytes({0b0000'0101});
    const std::vector<std::size_t> p_block{0, 1, 2, 3};

    const auto result = crypto::PermuteBits(
        input,
        p_block,
        crypto::BitOrder::LsbFirst,
        crypto::IndexBase::Zero
    );

    EXPECT_EQ(result, Bytes({0b0000'0101}));
}

TEST(PermuteBits, SupportsOneBasedIndexing) {
    const auto input = Bytes({0b1010'0000});
    const std::vector<std::size_t> p_block{1, 2, 3, 4};

    const auto result = crypto::PermuteBits(
        input,
        p_block,
        crypto::BitOrder::MsbFirst,
        crypto::IndexBase::One
    );

    EXPECT_EQ(result, Bytes({0b1010'0000}));
}

TEST(PermuteBits, ReversesFourMsbOrderedBits) {
    const auto input = Bytes({0b1010'0000});
    const std::vector<std::size_t> p_block{3, 2, 1, 0};

    const auto result = crypto::PermuteBits(
        input,
        p_block,
        crypto::BitOrder::MsbFirst,
        crypto::IndexBase::Zero
    );

    EXPECT_EQ(result, Bytes({0b0101'0000}));
}

TEST(PermuteBits, CanProduceMoreThanOneByte) {
    const auto input = Bytes({0b1111'0000, 0b1010'1010});
    const std::vector<std::size_t> p_block{0, 1, 2, 3, 8, 9, 10, 11, 4};

    const auto result = crypto::PermuteBits(
        input,
        p_block,
        crypto::BitOrder::MsbFirst,
        crypto::IndexBase::Zero
    );

    EXPECT_EQ(result, Bytes({0b1111'1010, 0b0000'0000}));
}

TEST(PermuteBits, EmptyPBlockProducesEmptyResult) {
    const auto input = Bytes({0b1010'0000});
    const std::vector<std::size_t> p_block;

    const auto result = crypto::PermuteBits(
        input,
        p_block,
        crypto::BitOrder::MsbFirst,
        crypto::IndexBase::Zero
    );

    EXPECT_TRUE(result.empty());
}

TEST(PermuteBits, AcceptsStdArrayInputs) {
    const std::array input{std::byte{0b1010'0000}};
    const std::array<std::size_t, 4> p_block{0, 1, 2, 3};

    const auto result = crypto::PermuteBits(
        input,
        p_block,
        crypto::BitOrder::MsbFirst,
        crypto::IndexBase::Zero
    );

    EXPECT_EQ(result, Bytes({0b1010'0000}));
}

TEST(PermuteBits, ThrowsWhenInputIsEmptyAndPBlockIsNotEmpty) {
    const std::vector<std::byte> input;
    const std::vector<std::size_t> p_block{0};

    EXPECT_THROW(
        static_cast<void>(crypto::PermuteBits(
            input,
            p_block,
            crypto::BitOrder::MsbFirst,
            crypto::IndexBase::Zero
        )),
        std::invalid_argument
    );
}

TEST(PermuteBits, ThrowsWhenZeroAppearsInOneBasedPBlock) {
    const auto input = Bytes({0b1010'0000});
    const std::vector<std::size_t> p_block{0};

    EXPECT_THROW(
        static_cast<void>(crypto::PermuteBits(
            input,
            p_block,
            crypto::BitOrder::MsbFirst,
            crypto::IndexBase::One
        )),
        std::invalid_argument
    );
}

TEST(PermuteBits, ThrowsWhenPBlockIndexIsOutsideInput) {
    const auto input = Bytes({0b1010'0000});
    const std::vector<std::size_t> p_block{8};

    EXPECT_THROW(
        static_cast<void>(crypto::PermuteBits(
            input,
            p_block,
            crypto::BitOrder::MsbFirst,
            crypto::IndexBase::Zero
        )),
        std::invalid_argument
    );
}
