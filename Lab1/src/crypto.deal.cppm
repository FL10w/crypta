export module crypto.deal;

import std;
import crypto.feistel;
import crypto.cipher;

export namespace crypto {
    class DEAL final : public SymmetricCipher {
    public:
        ~DEAL() override;

        DEAL();

        DEAL(const DEAL& rhs) = delete;
        DEAL& operator=(const DEAL& rhs) = delete;

        DEAL(DEAL&& rhs) noexcept;
        DEAL& operator=(DEAL&& rhs) noexcept;

        [[nodiscard]]
        std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const override;
        [[nodiscard]]
        std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const override;
        void SetKey(std::span<const std::byte> key) override;
        [[nodiscard]]
        std::size_t BlockSize() const override;

    private:
        class DEALImpl;
        std::unique_ptr<DEALImpl> deal_impl_;
    };
}