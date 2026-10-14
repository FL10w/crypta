export module crypto.bits;

import std;

export namespace crypto {
    enum class BitOrder {
        MsbFirst = 0,
        LsbFirst = 1,
    };

    enum class IndexBase {
        Zero = 0,
        One = 1,
    };

    std::vector<std::byte> PermuteBits(
        std::span<const std::byte> input,
        std::span<const std::size_t> p_block,
        BitOrder order,
        IndexBase base
    );
}
