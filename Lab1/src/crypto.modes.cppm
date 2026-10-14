export module crypto.modes;

import std;
import crypto.cipher;
import crypto.padding;

export namespace crypto {
    enum class CipherMode {
        ECB = 0,
        CBC = 1,
        PCBC = 2,
        CFB = 3,
        OFB = 4,
        CTR = 5,
        RandomDelta = 6,
    };

    class CipherModeStrategy {
    public:
        virtual ~CipherModeStrategy();

        [[nodiscard]]
        virtual std::vector<std::byte> Encrypt(
            const SymmetricCipher& cipher,
            std::span<const std::byte> data,
            PaddingMode padding_mode
        ) const = 0;

        [[nodiscard]]
        virtual std::vector<std::byte> Decrypt(
            const SymmetricCipher& cipher,
            std::span<const std::byte> data,
            PaddingMode padding_mode
        ) const = 0;
    };

    [[nodiscard]]
    std::unique_ptr<CipherModeStrategy> MakeCipherModeStrategy(
        CipherMode cipher_mode,
        std::span<const std::byte> iv = {},
        const std::vector<std::vector<std::byte>>& extra_parameters = {}
    );
}