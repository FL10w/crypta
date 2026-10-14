export module crypto.context;

import std;
import crypto.cipher;
import crypto.modes;
import crypto.padding;

export namespace crypto {
    class SymmetricCipherContext final {
    public:
        SymmetricCipherContext(
            std::unique_ptr<SymmetricCipher> cipher,
            std::span<const std::byte> key,
            CipherMode cipher_mode,
            PaddingMode padding_mode,
            std::span<const std::byte> iv = {},
            const std::vector<std::vector<std::byte>>& extra_parameters = {}
        );

        ~SymmetricCipherContext();

        SymmetricCipherContext(const SymmetricCipherContext& rhs) = delete;
        SymmetricCipherContext& operator=(const SymmetricCipherContext& rhs) = delete;

        SymmetricCipherContext(SymmetricCipherContext&& rhs) noexcept;
        SymmetricCipherContext& operator=(SymmetricCipherContext&& rhs) noexcept;

        [[nodiscard]]
        std::future<void> EncryptAsync(
            std::span<const std::byte> input,
            std::vector<std::byte>& result
        ) const;
        [[nodiscard]]
        std::future<void> DecryptAsync(
            std::span<const std::byte> input,
            std::vector<std::byte>& result
        ) const;

        [[nodiscard]]
        std::future<void> EncryptAsync(
            const std::filesystem::path& input_path,
            const std::filesystem::path& output_path
        ) const;
        [[nodiscard]]
        std::future<void> DecryptAsync(
            const std::filesystem::path& input_path,
            const std::filesystem::path& output_path
        ) const;

        // Compatibility aliases for existing clients.
        [[nodiscard]]
        std::future<void> EncryptFileAsync(
            const std::filesystem::path& input_path,
            const std::filesystem::path& output_path
        ) const;
        [[nodiscard]]
        std::future<void> DecryptFileAsync(
            const std::filesystem::path& input_path,
            const std::filesystem::path& output_path
        ) const;

    private:
        class SymmetricCipherContextImpl;
        std::shared_ptr<SymmetricCipherContextImpl> symmetric_cipher_context_impl_;
    };
}
