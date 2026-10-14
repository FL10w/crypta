export module crypto.cipher;

import std;

export namespace crypto {
    class KeyExpansion {
    public:
        virtual ~KeyExpansion() = default;

        [[nodiscard]]
        virtual std::vector<std::vector<std::byte>> GenerateRoundKeys(std::span<const std::byte> input_key) const = 0;
    };

    class RoundTransformation {
    public:
        virtual ~RoundTransformation() = default;

        [[nodiscard]]
        virtual std::vector<std::byte> Transform(
            std::span<const std::byte> input_block,
            std::span<const std::byte> round_key
        ) const = 0;
    };

    class SymmetricCipher {
    public:
        virtual ~SymmetricCipher() = default;

        [[nodiscard]]
        virtual std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const = 0;
        [[nodiscard]]
        virtual std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const = 0;

        virtual void SetKey(std::span<const std::byte> key) = 0;

        [[nodiscard]]
        virtual std::size_t BlockSize() const = 0;
    };
}
