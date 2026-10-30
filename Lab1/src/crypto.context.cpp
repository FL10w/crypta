module crypto.context;

import std;
import crypto.cipher;
import crypto.modes;
import crypto.padding;

namespace crypto {
    class SymmetricCipherContext::SymmetricCipherContextImpl {
    public:
        SymmetricCipherContextImpl(
            std::unique_ptr<SymmetricCipher> cipher,
            std::span<const std::byte> key,
            CipherMode cipher_mode,
            PaddingMode padding_mode,
            std::span<const std::byte> iv,
            const std::vector<std::vector<std::byte>>& extra_parameters
        )
        :
            cipher_(std::move(cipher)),
            cipher_mode_strategy_(MakeCipherModeStrategy(
                cipher_mode,
                iv,
                extra_parameters
            )),
            padding_mode_(padding_mode),
            cipher_mode_(cipher_mode),
            iv_(iv.begin(), iv.end()),
            extra_parameters_(extra_parameters)
        {
            if (!cipher_) {
                throw std::invalid_argument("cipher is null");
            }

            cipher_->SetKey(key);
        }

        ~SymmetricCipherContextImpl() = default;

        [[nodiscard]]
        std::vector<std::byte> Encrypt(std::span<const std::byte> input) const {
            return cipher_mode_strategy_->Encrypt(*cipher_, input, padding_mode_);
        }
        [[nodiscard]]
        std::vector<std::byte> Decrypt(std::span<const std::byte> input) const {
            return cipher_mode_strategy_->Decrypt(*cipher_, input, padding_mode_);
        }

        void ProcessFile(
            const std::filesystem::path& input_path,
            const std::filesystem::path& output_path,
            bool decrypt
        ) const {
            std::ifstream input(input_path, std::ios::binary);
            if (!input) throw std::runtime_error("unable to open input file");
            if (std::filesystem::exists(output_path) &&
                std::filesystem::equivalent(input_path, output_path)) {
                throw std::invalid_argument("input and output files must be different");
            }

            const auto block_size = cipher_->BlockSize();
            if (block_size == 0) throw std::invalid_argument("invalid block size");
            const auto chunk_size = std::max(block_size, (64 * 1024 / block_size) * block_size);
            std::vector<std::byte> buffer(chunk_size);
            // Feedback and counters belong to this operation, not to the shared context.
            auto mode = MakeCipherModeStrategy(cipher_mode_, iv_, extra_parameters_);
            std::ofstream output(output_path, std::ios::binary);
            if (!output) throw std::runtime_error("unable to open output file");

            std::uintmax_t written = 0;
            std::uintmax_t trailing_zeros = 0;
            for (;;) {
                input.read(reinterpret_cast<char*>(buffer.data()),
                    static_cast<std::streamsize>(buffer.size()));
                const auto count = static_cast<std::size_t>(input.gcount());
                if (input.bad() || (input.fail() && !input.eof())) {
                    throw std::runtime_error("unable to read input file");
                }
                const bool last = input.eof() || input.peek() == std::char_traits<char>::eof();
                if (input.bad()) throw std::runtime_error("unable to read input file");
                const auto chunk = std::span<const std::byte>{buffer}.first(count);

                auto result = decrypt
                    ? mode->Decrypt(*cipher_, chunk, padding_mode_, false)
                    : mode->Encrypt(*cipher_, chunk, padding_mode_, last);
                if (!last) {
                    mode->AdvanceState(decrypt ? std::span<const std::byte>{result} : chunk,
                        decrypt ? chunk : std::span<const std::byte>{result});
                }
                if (decrypt) {
                    if (padding_mode_ == PaddingMode::Zeros) {
                        const auto nonzero = std::find_if(result.rbegin(), result.rend(),
                            [](std::byte value) { return value != std::byte{0}; });
                        const auto zeros = static_cast<std::size_t>(nonzero - result.rbegin());
                        trailing_zeros = zeros == result.size() ? trailing_zeros + zeros : zeros;
                    } else if (last) {
                        result = RemovePadding(result, block_size, padding_mode_);
                    }
                }
                if (!result.empty()) {
                    output.write(reinterpret_cast<const char*>(result.data()),
                        static_cast<std::streamsize>(result.size()));
                }
                if (!output) throw std::runtime_error("unable to write to output file");
                written += result.size();
                if (last) break;
            }
            output.close();
            if (!output) throw std::runtime_error("unable to close output file");
            if (decrypt && padding_mode_ == PaddingMode::Zeros) {
                // The zero suffix can span several chunks. Preserve one zero byte
                // for an all-zero message, just as RemoveZerosPadding does.
                std::filesystem::resize_file(output_path, std::max<std::uintmax_t>(1, written - trailing_zeros));
            }
        }
    private:
        std::unique_ptr<SymmetricCipher> cipher_;
        std::unique_ptr<CipherModeStrategy> cipher_mode_strategy_;
        PaddingMode padding_mode_;
        CipherMode cipher_mode_;
        std::vector<std::byte> iv_;
        std::vector<std::vector<std::byte>> extra_parameters_;
    };

    SymmetricCipherContext::SymmetricCipherContext(
        std::unique_ptr<SymmetricCipher> cipher,
        std::span<const std::byte> key,
        CipherMode cipher_mode,
        PaddingMode padding_mode,
        std::span<const std::byte> iv,
        const std::vector<std::vector<std::byte>>& extra_parameters
    ) : symmetric_cipher_context_impl_(std::make_shared<SymmetricCipherContextImpl>(
            std::move(cipher),
            key,
            cipher_mode,
            padding_mode,
            iv,
            extra_parameters
        )
    ) {}

    SymmetricCipherContext::~SymmetricCipherContext() = default;

    SymmetricCipherContext::SymmetricCipherContext(SymmetricCipherContext&& rhs) noexcept = default;
    SymmetricCipherContext& SymmetricCipherContext::operator=(SymmetricCipherContext&& rhs) noexcept = default;

    std::future<void> SymmetricCipherContext::EncryptAsync(
        std::span<const std::byte> input,
        std::vector<std::byte>& result
    ) const {
        std::vector input_copy(input.begin(), input.end());

        return std::async(
            std::launch::async,
            [impl = symmetric_cipher_context_impl_, input_copy = std::move(input_copy), &result]() {
                result = impl->Encrypt(input_copy);
            }
        );
    }

    std::future<void> SymmetricCipherContext::DecryptAsync(
        std::span<const std::byte> input,
        std::vector<std::byte>& result
    ) const {
        std::vector input_copy(input.begin(), input.end());

        return std::async(
            std::launch::async,
            [impl = symmetric_cipher_context_impl_, input_copy = std::move(input_copy), &result]() {
                result = impl->Decrypt(input_copy);
            }
        );
    }

    std::future<void> SymmetricCipherContext::EncryptAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return std::async(
            std::launch::async,
            [impl = symmetric_cipher_context_impl_, input_path, output_path]() {
                impl->ProcessFile(input_path, output_path, false);
            }
        );
    }

    std::future<void> SymmetricCipherContext::DecryptAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return std::async(
            std::launch::async,
            [impl = symmetric_cipher_context_impl_, input_path, output_path]() {
                impl->ProcessFile(input_path, output_path, true);
            }
        );
    }

    std::future<void> SymmetricCipherContext::EncryptFileAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return EncryptAsync(input_path, output_path);
    }

    std::future<void> SymmetricCipherContext::DecryptFileAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return DecryptAsync(input_path, output_path);
    }
}
