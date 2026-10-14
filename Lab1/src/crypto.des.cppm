export module crypto.des;

import std;
import crypto.cipher;
import crypto.feistel;

export namespace crypto {
    class DES final : public SymmetricCipher {
    public:
        ~DES() override;

        DES();

        DES(const DES& rhs) = delete;
        DES& operator=(const DES& rhs) = delete;

        DES(DES&& rhs) noexcept;
        DES& operator=(DES&& rhs) noexcept;

        [[nodiscard]]
        std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const override;
        [[nodiscard]]
        std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const override;
        void SetKey(std::span<const std::byte> key) override;
        [[nodiscard]]
        std::size_t BlockSize() const override;

    private:
        class DESImpl;
        std::unique_ptr<DESImpl> des_impl_;
    };
}