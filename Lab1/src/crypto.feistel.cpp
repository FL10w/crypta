module crypto.feistel;

import std;
import crypto.cipher;

namespace crypto {
    namespace {
        void ValidateBlockSize(std::size_t block_size) {
            if (block_size == 0 || block_size & 1) {
                throw std::invalid_argument("feistel block size has to be positive even");
            }
        }

        void ValidateBlock(std::span<const std::byte> block, std::size_t expected_block_size) {
            if (block.size() != expected_block_size) {
                throw std::invalid_argument("block size has to be equal to expected");
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

        std::vector<std::byte> JoinHalves(std::span<const std::byte> lhs, std::span<const std::byte> rhs) {
            std::vector<std::byte> result;
            result.reserve(lhs.size() + rhs.size());

            result.insert(result.end(), lhs.begin(), lhs.end());
            result.insert(result.end(), rhs.begin(), rhs.end());

            return result;
        }
    }

    class FeistelNetwork::FeistelNetworkImpl {
    public:
        FeistelNetworkImpl(
            std::unique_ptr<const KeyExpansion> key_expansion,
            std::unique_ptr<const RoundTransformation> round_transformation,
            std::size_t block_size
        ) :
        key_expansion_(std::move(key_expansion)),
        round_transformation_(std::move(round_transformation)),
        block_size_(block_size) {
            if (!key_expansion_) {
                throw std::invalid_argument("key expansion has to be non-null");
            }
            if (!round_transformation_) {
                throw std::invalid_argument("round transformation has to be non-null");
            }
            ValidateBlockSize(block_size_);
        }

        [[nodiscard]]
        std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const {
            ValidateRoundKeys();
            ValidateBlock(block, block_size_);

            return Transform(block ,false);
        }

        [[nodiscard]]
        std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const {
            ValidateRoundKeys();
            ValidateBlock(block, block_size_);

            return Transform(block ,true);
        }

        void SetKey(std::span<const std::byte> key) {
            round_keys_ = key_expansion_->GenerateRoundKeys(key);
            ValidateRoundKeys();
        }

        [[nodiscard]]
        std::size_t BlockSize() const {
            return block_size_;
        }

    private:
        void ValidateRoundKeys() const {
            if (round_keys_.empty()) {
                throw std::invalid_argument("round keys have not been set");
            }
        }

        [[nodiscard]]
        std::vector<std::byte> Transform(std::span<const std::byte> block, bool is_decrypt) const {
            const auto half_size = block_size_ >> 1;

            std::vector<std::byte> left;
            left.assign(block.begin(), block.begin() + static_cast<std::ptrdiff_t>(half_size));

            std::vector<std::byte> right;
            right.assign(block.begin() + static_cast<std::ptrdiff_t>(half_size), block.end());

            for (std::size_t round = 0; round < round_keys_.size(); ++round) {
                const auto key_index = is_decrypt ? round_keys_.size() - 1 - round : round;
                const auto f_result = round_transformation_->Transform(right, round_keys_[key_index]);
                ValidateBlock(f_result, half_size);

                const auto new_left = right;
                const auto new_right = XORBlocks(f_result, left);

                left = new_left;
                right = new_right;
            }

            return JoinHalves(right, left);
        }

    private:
        std::shared_ptr<const KeyExpansion> key_expansion_;
        std::shared_ptr<const RoundTransformation> round_transformation_;
        std::size_t block_size_;
        std::vector<std::vector<std::byte>> round_keys_;
    };

    FeistelNetwork::~FeistelNetwork() = default;

    FeistelNetwork::FeistelNetwork(
        std::unique_ptr<const KeyExpansion> key_expansion,
        std::unique_ptr<const RoundTransformation> round_transformation,
        std::size_t block_size
    ) : feistel_network_impl_(std::make_unique<FeistelNetworkImpl>(
        std::move(key_expansion),
        std::move(round_transformation),
        block_size
    )) {}

    FeistelNetwork::FeistelNetwork(FeistelNetwork&& rhs) noexcept = default;
    FeistelNetwork& FeistelNetwork::operator=(FeistelNetwork&& rhs) noexcept = default;

    std::vector<std::byte> FeistelNetwork::EncryptBlock(std::span<const std::byte> block) const {
        return feistel_network_impl_->EncryptBlock(block);
    }

    std::vector<std::byte> FeistelNetwork::DecryptBlock(std::span<const std::byte> block) const {
        return feistel_network_impl_->DecryptBlock(block);
    }

    void FeistelNetwork::SetKey(std::span<const std::byte> key) {
        feistel_network_impl_->SetKey(key);
    }

    std::size_t FeistelNetwork::BlockSize() const {
        return feistel_network_impl_->BlockSize();
    }
}
