export module crypto.feistel;

import std;
import crypto.cipher;

export namespace crypto {
    class FeistelNetwork final : public SymmetricCipher {
    public:
        ~FeistelNetwork() override;

        FeistelNetwork(
            std::unique_ptr<const KeyExpansion> key_expansion,
            std::unique_ptr<const RoundTransformation> round_transformation,
            std::size_t block_size
        );

        FeistelNetwork(const FeistelNetwork& rhs) = delete;
        FeistelNetwork& operator=(const FeistelNetwork& rhs) = delete;

        FeistelNetwork(FeistelNetwork&& rhs) noexcept;
        FeistelNetwork& operator=(FeistelNetwork&& rhs) noexcept;

        std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const override;
        std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const override;
        void SetKey(std::span<const std::byte> key) override;
        std::size_t BlockSize() const override;
    private:
        class FeistelNetworkImpl;
        std::unique_ptr<FeistelNetworkImpl> feistel_network_impl_;
    };
}
