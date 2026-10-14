module crypto.bits;

import std;

namespace crypto {
    namespace {
        bool GetBit(std::byte byte, std::uint8_t index, BitOrder order) {
            if (index > 7) {
                throw std::invalid_argument("index out of range (0-7) for bit");
            }

            const std::uint8_t shift = order == BitOrder::MsbFirst ? 7 - index : index;

            return ((byte >> shift) & std::byte{1}) != std::byte{0};
        }

        void SetBit(std::byte& byte, std::uint8_t index, bool bit, BitOrder order) {
            if (index > 7) {
                throw std::invalid_argument("index out of range (0-7) for bit");
            }

            const std::size_t shift = order == BitOrder::MsbFirst ? 7 - index : index;

            if (bit) {
                byte |= std::byte{1} << shift;
            } else {
                byte &= ~(std::byte{1} << shift);
            }
        }
    }

    std::vector<std::byte> PermuteBits(
        std::span<const std::byte> input,
        std::span<const std::size_t> p_block,
        BitOrder order,
        IndexBase base
    ) {
        std::vector<std::byte> permuted((p_block.size() + 7) >> 3);

        for (std::size_t i = 0; i < p_block.size(); ++i) {
            std::size_t index = p_block[i];
            if (base == IndexBase::One) {
                if (index == 0) {
                    throw std::invalid_argument("zero index in one-based p_block");
                }
                --index;
            }
            if (index >= input.size() << 3) {
                throw std::invalid_argument("invalid index in p_block");
            }

            const bool bit = GetBit(input[index >> 3], index & 7, order);
            SetBit(permuted[i >> 3], i & 7, bit, order);
        }

        return permuted;
    }
}
