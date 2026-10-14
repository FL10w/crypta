module crypto.deal;

import std;
import crypto.cipher;
import crypto.des;

namespace crypto {
    namespace {
        inline constexpr std::size_t kDEALBlockSize = 16;
        inline constexpr std::size_t kDEALRoundKeySize = 8;
        // Constant masks, in DES's MSB-first byte representation.
        inline constexpr std::array<std::byte, 4> kDEALMasks{
            std::byte{0x80}, std::byte{0x40}, std::byte{0x20}, std::byte{0x10}
        };
        inline constexpr std::array kDEALScheduleKey = {
            std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
            std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
        };


        void ValidateDEALBlock(std::span<const std::byte> block) {
            if (block.size() != kDEALBlockSize) {
                throw std::invalid_argument("invalid DEAL block size");
            }
        }

        void ValidateDEALKey(std::span<const std::byte> key) {
            if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
                throw std::invalid_argument("invalid DEAL key size");
            }
        }

        void ValidateDEALRoundKey(std::span<const std::byte> key) {
            if (key.size() != kDEALRoundKeySize) {
                throw std::invalid_argument("invalid DEAL round key size");
            }
        }

        std::vector<std::byte> XORBlocks(std::span<const std::byte> lhs, std::span<const std::byte> rhs) {
            if (lhs.size() != rhs.size()) {
                throw std::invalid_argument("blocks have different sizes");
            }

            std::vector<std::byte> output(lhs.size());
            for (std::size_t i = 0; i < output.size(); ++i) {
                output[i] = lhs[i] ^ rhs[i];
            }

            return output;
        }

        class DEALKeyExpansion final : public KeyExpansion {
        public:
            [[nodiscard]]
            std::vector<std::vector<std::byte>> GenerateRoundKeys(std::span<const std::byte> input_key) const override {
                ValidateDEALKey(input_key);

                const auto parts = input_key.size() / kDEALRoundKeySize;
                const auto rounds = parts == 4 ? 8u : 6u;
                DES schedule;
                schedule.SetKey(kDEALScheduleKey);
                std::vector<std::vector<std::byte>> round_keys;
                round_keys.reserve(rounds);
                std::vector previous(kDEALRoundKeySize, std::byte{0});
                for (std::size_t round = 0; round < rounds; ++round) {
                    auto block = XORBlocks(input_key.subspan((round % parts) * kDEALRoundKeySize,
                        kDEALRoundKeySize), previous);
                    if (round >= parts) {
                        block.front() ^= kDEALMasks[round - parts];
                    }
                    previous = schedule.EncryptBlock(block);
                    round_keys.push_back(previous);
                }

                return round_keys;
            }
        };

        class DEALRoundTransformation final : public RoundTransformation {
        public:
            [[nodiscard]]
            std::vector<std::byte> Transform(
                std::span<const std::byte> input_block,
                std::span<const std::byte> round_key
            ) const override {
                if (input_block.size() != kDEALBlockSize >> 1) {
                    throw std::invalid_argument("invalid DEAL input block size");
                }
                ValidateDEALRoundKey(round_key);

                DES des;
                des.SetKey(round_key);

                return des.EncryptBlock(input_block);
            }
        };
    }

    class DEAL::DEALImpl {
    public:
        DEALImpl() : feistel_network_(
            std::make_unique<DEALKeyExpansion>(),
            std::make_unique<DEALRoundTransformation>(),
            kDEALBlockSize
        ) {}

        [[nodiscard]]
        std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const {
            ValidateDEALBlock(block);

            // DEAL feeds the left input half into F in its first round.
            // The shared DES-style network feeds the right half into F and
            // returns swapped halves, so adapt the input order here.
            std::vector swapped(block.begin(), block.end());
            std::ranges::rotate(swapped, swapped.begin() + kDEALBlockSize / 2);
            return feistel_network_.EncryptBlock(swapped);
        }

        [[nodiscard]]
        std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const {
            ValidateDEALBlock(block);

            auto result = feistel_network_.DecryptBlock(block);
            std::ranges::rotate(result, result.begin() + kDEALBlockSize / 2);
            return result;
        }

        void SetKey(std::span<const std::byte> key) {
            feistel_network_.SetKey(key);
        }

        static std::size_t BlockSize() {
            return kDEALBlockSize;
        }

    private:
        FeistelNetwork feistel_network_;
    };

    DEAL::~DEAL() = default;

    DEAL::DEAL() : deal_impl_(std::make_unique<DEALImpl>()) {}

    DEAL::DEAL(DEAL&& rhs) noexcept = default;
    DEAL& DEAL::operator=(DEAL&& rhs) noexcept = default;

    std::vector<std::byte> DEAL::EncryptBlock(std::span<const std::byte> block) const {
        return deal_impl_->EncryptBlock(block);
    }

    std::vector<std::byte> DEAL::DecryptBlock(std::span<const std::byte> block) const {
        return deal_impl_->DecryptBlock(block);
    }

    void DEAL::SetKey(std::span<const std::byte> key) {
        deal_impl_->SetKey(key);
    }

    std::size_t DEAL::BlockSize() const {
        return DEALImpl::BlockSize();
    }
}
