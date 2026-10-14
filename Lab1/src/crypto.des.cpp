module crypto.des;

import std;
import crypto.cipher;
import crypto.feistel;
import crypto.bits;

namespace crypto {
    namespace {
        inline constexpr std::size_t kDESBlockSize = 8;
        inline constexpr std::size_t kDESKeySize = 8;
        inline constexpr std::size_t kDESRoundKeySize = 6;
        inline constexpr std::size_t kDESRoundCount = 16;

        inline constexpr std::array<std::size_t, 64> kIP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
        };
        inline constexpr std::array<std::size_t, 64> kIPInv = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25,
        };
        inline constexpr std::array<std::size_t, 48> kE = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1,
        };
        inline constexpr std::array<std::size_t, 32> kP = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25,
        };
        inline constexpr std::array<std::size_t, 56> kPC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,

            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4,
        };
        inline constexpr std::array<std::size_t, 48> kPC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32,
        };
        inline constexpr std::array<std::array<std::size_t, 64>, 8> kS{{
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
            },
        }};
        inline constexpr std::array<std::size_t, 16> kShifts = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
        };

        void ValidateDESBlock(std::span<const std::byte> block) {
            if (block.size() != kDESBlockSize) {
                throw std::invalid_argument("invalid DES block size");
            }
        }

        void ValidateDESKey(std::span<const std::byte> key) {
            if (key.size() != kDESKeySize) {
                throw std::invalid_argument("invalid DES key size");
            }
        }

        void ValidateDESRoundKey(std::span<const std::byte> key) {
            if (key.size() != kDESRoundKeySize) {
                throw std::invalid_argument("invalid DES key size");
            }
        }

        std::vector<std::uint8_t> BytesToBits(std::span<const std::byte> bytes, std::size_t bits_count) {
            std::vector<std::uint8_t> bits;
            bits.reserve(bits_count);

            for (std::size_t i = 0; i < bits_count; ++i) {
                const auto byte_i = i >> 3;
                const auto bit_i = 7 - i & 7;
                const auto bit = bytes[byte_i] >> bit_i & std::byte{1};
                bits.push_back(bit != std::byte{0});
            }

            return bits;
        }

        std::vector<std::byte> BitsToBytes(std::span<const std::uint8_t> bits) {
            std::vector bytes((bits.size() + 7) >> 3, std::byte{0});

            for (std::size_t i = 0; i < bits.size(); ++i) {
                if (bits[i] == 0) {
                    continue;
                }

                const auto byte_i = i >> 3;
                const auto bit_i = 7 - i & 7;

                bytes[byte_i] |= std::byte{1} << bit_i;
            }

            return bytes;
        }

        class DESKeyExpansion final : public KeyExpansion {
        public:
            [[nodiscard]]
            std::vector<std::vector<std::byte>> GenerateRoundKeys(std::span<const std::byte> input_key) const override {
                ValidateDESKey(input_key);

                const auto key56 = PermuteBits(input_key, kPC1, BitOrder::MsbFirst, IndexBase::One);
                const auto key_bits = BytesToBits(key56, 56);

                std::vector c(key_bits.begin(), key_bits.begin() + 28);
                std::vector d(key_bits.begin() + 28, key_bits.end());

                std::vector<std::vector<std::byte>> round_keys;
                round_keys.reserve(kDESRoundCount);

                for (std::size_t round = 0; round < kDESRoundCount; ++round) {
                    std::ranges::rotate(c, c.begin() + static_cast<std::ptrdiff_t>(kShifts[round]));
                    std::ranges::rotate(d, d.begin() + static_cast<std::ptrdiff_t>(kShifts[round]));

                    std::vector<std::uint8_t> cd;
                    cd.reserve(56);

                    cd.insert(cd.end(), c.begin(), c.end());
                    cd.insert(cd.end(), d.begin(), d.end());

                    const auto cd_bytes = BitsToBytes(cd);
                    round_keys.push_back(PermuteBits(cd_bytes, kPC2, BitOrder::MsbFirst, IndexBase::One));
                }

                return round_keys;
            }
        };

        class DESRoundTransformation final : public RoundTransformation {
        public:
            [[nodiscard]]
            std::vector<std::byte> Transform(
                std::span<const std::byte> input_block,
                std::span<const std::byte> round_key
            ) const override {
                if (input_block.size() != kDESBlockSize >> 1) {
                    throw std::invalid_argument("invalid DES input block size");
                }

                ValidateDESRoundKey(round_key);

                auto expanded = PermuteBits(input_block, kE, BitOrder::MsbFirst, IndexBase::One);

                for (std::size_t i = 0; i < expanded.size(); ++i) {
                    expanded[i] ^= round_key[i];
                }

                const auto expanded_bits = BytesToBits(expanded, 48);

                std::vector<std::uint8_t> sbox_bites;
                sbox_bites.reserve(32);

                for (std::size_t sbox = 0; sbox < kS.size(); ++sbox) {
                    const auto offset = sbox * 6;

                    const auto row = expanded_bits[offset] << 1 | expanded_bits[offset + 5];
                    const auto col = expanded_bits[offset + 1] << 3 | expanded_bits[offset + 2] << 2 |
                        expanded_bits[offset + 3] << 1 | expanded_bits[offset + 4];

                    const auto value = kS[sbox][row * 16 + col];

                    sbox_bites.push_back((value >> 3) & 1);
                    sbox_bites.push_back((value >> 2) & 1);
                    sbox_bites.push_back((value >> 1) & 1);
                    sbox_bites.push_back(value & 1);
                }

                const auto sbox = BitsToBytes(sbox_bites);

                return PermuteBits(sbox, kP, BitOrder::MsbFirst, IndexBase::One);
            }
        };
    }

    class DES::DESImpl {
    public:
        DESImpl() : feistel_network_(
            std::make_unique<DESKeyExpansion>(),
            std::make_unique<DESRoundTransformation>(),
            kDESBlockSize
        ){}

        [[nodiscard]]
        std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const {
            ValidateDESBlock(block);

            const auto ip = PermuteBits(block, kIP, BitOrder::MsbFirst, IndexBase::One);
            const auto feistel = feistel_network_.EncryptBlock(ip);
            const auto ip_inv = PermuteBits(feistel, kIPInv, BitOrder::MsbFirst, IndexBase::One);

            return ip_inv;
        }

        [[nodiscard]]
        std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const {
            ValidateDESBlock(block);

            const auto ip = PermuteBits(block, kIP, BitOrder::MsbFirst, IndexBase::One);
            const auto feistel = feistel_network_.DecryptBlock(ip);
            const auto ip_inv = PermuteBits(feistel, kIPInv, BitOrder::MsbFirst, IndexBase::One);

            return ip_inv;
        }

        void SetKey(std::span<const std::byte> key) {
            ValidateDESKey(key);
            feistel_network_.SetKey(key);
        }

        static std::size_t BlockSize() {
            return kDESBlockSize;
        }

    private:
        FeistelNetwork feistel_network_;
    };

    DES::~DES() = default;

    DES::DES() : des_impl_(std::make_unique<DESImpl>()) {}

    DES::DES(DES&& rhs) noexcept = default;
    DES& DES::operator=(DES&& rhs) noexcept = default;

    std::vector<std::byte> DES::EncryptBlock(std::span<const std::byte> block) const {
        return des_impl_->EncryptBlock(block);
    }

    std::vector<std::byte> DES::DecryptBlock(std::span<const std::byte> block) const {
        return des_impl_->DecryptBlock(block);
    }

    void DES::SetKey(std::span<const std::byte> key) {
        des_impl_->SetKey(key);
    }

    std::size_t DES::BlockSize() const {
        return DESImpl::BlockSize();
    }
}
