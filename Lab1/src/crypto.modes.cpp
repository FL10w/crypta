module crypto.modes;

import std;

namespace crypto {
    namespace {
        void ValidateBlockSize(std::size_t block_size) {
            if (block_size == 0) {
                throw std::invalid_argument("invalid block size");
            }
        }

        void ValidateBlockAlignedData(
            std::span<const std::byte> data,
            std::size_t block_size,
            std::string_view mode_name
        ) {
            ValidateBlockSize(block_size);

            if (data.empty() || data.size() % block_size != 0) {
                throw std::invalid_argument(std::format("invalid data size for {} mode", mode_name));
            }
        }

        void ValidateIVSize(std::span<const std::byte> iv, std::size_t expected_size, std::string_view mode_name) {
            if (iv.size() != expected_size) {
                throw std::invalid_argument(std::format("invalid IV size for {} mode", mode_name));
            }
        }

        void ValidateOutputBlockSize(std::span<const std::byte> block, std::size_t block_size, std::string_view mode_name) {
            if (block.size() != block_size) {
                throw std::logic_error(std::format("invalid output block size for {} mode", mode_name));
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

        void AppendBlock(std::vector<std::byte>& vector, std::span<const std::byte> block) {
            vector.insert(vector.end(), block.begin(), block.end());
        }

        std::vector<std::byte> MakeCounterBlock(std::span<const std::byte> iv, std::uint64_t counter) {
            std::vector counter_block(iv.begin(), iv.end());

            for (std::size_t i = counter_block.size(); i > 0 && counter != 0; --i) {
                const auto index = i - 1;

                const auto sum = static_cast<std::uint8_t>(counter_block[index]) +
                    static_cast<std::uint8_t>(counter & 0xFF);

                counter_block[index] = static_cast<std::byte>(sum & 0xFF);
                counter = (counter >> 8) + (sum >> 8);
            }

            return counter_block;
        }

        std::vector<std::byte> MakeRandomDeltaState(
            std::span<const std::byte> iv,
            std::span<const std::byte> delta,
            std::size_t block_index
        ) {
            std::vector state(iv.begin(), iv.end());

            for (std::size_t delta_pos = 0; delta_pos < delta.size(); ++delta_pos) {
                const auto delta_index = delta.size() - delta_pos - 1;

                auto multiplier = block_index;
                auto carry = std::uint64_t{0};

                for (std::size_t multiplier_pos = 0; multiplier != 0 || carry != 0; ++multiplier_pos) {
                    const auto state_pos = delta_pos + multiplier_pos;
                    if (state_pos >= state.size()) {
                        break;
                    }

                    const auto state_index = state.size() - state_pos - 1;
                    const auto product = static_cast<std::uint64_t>(delta[delta_index]) * (multiplier & 0xFF) +
                        static_cast<std::uint64_t>(state[state_index]) + carry;

                    state[state_index] = static_cast<std::byte>(product & 0xFF);

                    carry = product >> 8;
                    multiplier >>= 8;
                }
            }

            return state;
        }

        template<typename Func>
        std::vector<std::byte> ProcessBlocksParallel(
            std::span<const std::byte> data,
            std::size_t block_size,
            std::string_view mode_name,
            Func process_block
        ) {
            ValidateBlockAlignedData(data, block_size, mode_name);

            const auto blocks_count = data.size() / block_size;

            std::vector<std::byte> result(data.size());

            const auto all_threads = std::max(1u, std::thread::hardware_concurrency());
            const auto threads_count = std::min<std::size_t>(
                all_threads, (blocks_count + 31) / 32
            );

            if (threads_count < 2 || blocks_count < 2) {
                for (std::size_t block_i = 0; block_i < blocks_count; ++block_i) {
                    const auto offset = block_i * block_size;
                    const auto block = std::span{data.data() + offset, block_size};
                    const auto result_block = process_block(block, block_i);
                    ValidateOutputBlockSize(result_block, block_size, mode_name);
                    std::ranges::copy(result_block, result.begin() + static_cast<std::ptrdiff_t>(offset));
                }

                return result;
            }

            std::vector<std::exception_ptr> exceptions(threads_count);
            // Join workers before destroying their exception storage, even if
            // creating a later worker throws.
            std::vector<std::jthread> threads;
            threads.reserve(threads_count);

            const auto blocks_per_thread = (blocks_count + threads_count - 1) / threads_count;

            for (std::size_t thread_i = 0; thread_i < threads_count; ++thread_i) {
                const auto first_block = thread_i * blocks_per_thread;
                const auto last_block = std::min(blocks_count, first_block + blocks_per_thread);

                threads.emplace_back([&, thread_i, first_block, last_block]() {
                    try {
                        for (std::size_t block_i = first_block; block_i < last_block; ++block_i) {
                            const auto offset = block_i * block_size;
                            const auto block = std::span{data.data() + offset, block_size};
                            const auto result_block = process_block(block, block_i);
                            ValidateOutputBlockSize(result_block, block_size, mode_name);
                            std::ranges::copy(result_block, result.begin() + static_cast<std::ptrdiff_t>(offset));
                        }
                    } catch (...) {
                        exceptions[thread_i] = std::current_exception();
                    }
                });
            }

            for (auto& thread : threads) {
                thread.join();
            }

            for (const auto& exception : exceptions) {
                if (exception) {
                    std::rethrow_exception(exception);
                }
            }

            return result;
        }

        class ECBMode final : public CipherModeStrategy {
        public:
            ~ECBMode() override = default;

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);

                const auto padded = AddPadding(data, block_size, padding_mode);

                return ProcessBlocksParallel(
                    padded,
                    block_size,
                    "ecb",
                    [&](std::span<const std::byte> block, std::size_t index) {
                        return cipher.EncryptBlock(block);
                    }
                );
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "ecb");

                const auto decrypted = ProcessBlocksParallel(
                    data,
                    block_size,
                    "ecb",
                    [&](std::span<const std::byte> block, std::size_t index) {
                        return cipher.DecryptBlock(block);
                    }
                );

                return RemovePadding(decrypted, block_size, padding_mode);
            }
        };

        class CBCMode final : public CipherModeStrategy {
        public:
            ~CBCMode() override = default;

            explicit CBCMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                ValidateIVSize(iv_, block_size, "cbc");

                const auto padded = AddPadding(data, block_size, padding_mode);

                std::vector<std::byte> result;
                result.reserve(padded.size());

                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < padded.size(); offset += block_size) {
                    const auto block = std::span{padded.data() + offset, block_size};
                    const auto encrypted = cipher.EncryptBlock(XORBlocks(block, prev_cipher_block));
                    ValidateOutputBlockSize(encrypted, block_size, "cbc");
                    AppendBlock(result, encrypted);

                    prev_cipher_block = encrypted;
                }

                return result;
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "cbc");
                ValidateIVSize(iv_, block_size, "cbc");

                const auto decrypted_blocks = ProcessBlocksParallel(
                    data,
                    block_size,
                    "cbc",
                    [&](std::span<const std::byte> block, std::size_t index) {
                        return cipher.DecryptBlock(block);
                    }
                );

                std::vector<std::byte> result;
                result.reserve(data.size());

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    const auto decrypted_block = std::span{decrypted_blocks.data() + offset, block_size};
                    const auto previous_cipher_block = offset == 0 ? std::span{iv_} :
                        std::span{data.data() + offset - block_size, block_size};
                    const auto block = XORBlocks(decrypted_block, previous_cipher_block);
                    AppendBlock(result, block);
                }

                return RemovePadding(result, block_size, padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class PCBCMode final : public CipherModeStrategy {
        public:
            ~PCBCMode() override = default;

            explicit PCBCMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                ValidateIVSize(iv_, block_size, "pcbc");

                const auto padded = AddPadding(data, block_size, padding_mode);

                std::vector<std::byte> result;
                result.reserve(padded.size());

                auto prev_block = std::vector(block_size, std::byte{0});
                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < padded.size(); offset += block_size) {
                    const auto block = std::span{padded.data() + offset, block_size};
                    const auto encrypted = cipher.EncryptBlock(XORBlocks(XORBlocks(block, prev_block), prev_cipher_block));
                    ValidateOutputBlockSize(encrypted, block_size, "pcbc");
                    AppendBlock(result, encrypted);

                    prev_block.assign(block.begin(), block.end());
                    prev_cipher_block = encrypted;
                }

                return result;
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "pcbc");
                ValidateIVSize(iv_, block_size, "pcbc");

                const auto decrypted_blocks = ProcessBlocksParallel(
                    data, block_size, "pcbc",
                    [&](std::span<const std::byte> block, std::size_t) {
                        return cipher.DecryptBlock(block);
                    }
                );

                std::vector<std::byte> result;
                result.reserve(data.size());

                auto prev_block = std::vector(block_size, std::byte{0});
                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    const auto cipher_block = std::span{data.data() + offset, block_size};
                    const auto decrypted = std::span{decrypted_blocks}.subspan(offset, block_size);
                    const auto block = XORBlocks(XORBlocks(decrypted, prev_block), prev_cipher_block);
                    AppendBlock(result, block);

                    prev_block = block;
                    prev_cipher_block.assign(cipher_block.begin(), cipher_block.end());
                }

                return RemovePadding(result, block_size, padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class CFBMode final : public CipherModeStrategy {
        public:
            ~CFBMode() override = default;

            explicit CFBMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                ValidateIVSize(iv_, block_size, "cfb");

                const auto padded = AddPadding(data, block_size, padding_mode);

                std::vector<std::byte> result;
                result.reserve(padded.size());

                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < padded.size(); offset += block_size) {
                    const auto block = std::span{padded.data() + offset, block_size};
                    const auto gamma = cipher.EncryptBlock(prev_cipher_block);
                    ValidateOutputBlockSize(gamma, block_size, "cfb");
                    const auto encrypted = XORBlocks(block, gamma);
                    AppendBlock(result, encrypted);

                    prev_cipher_block = encrypted;
                }

                return result;
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "cfb");
                ValidateIVSize(iv_, block_size, "cfb");

                const auto result = ProcessBlocksParallel(
                    data, block_size, "cfb",
                    [&](std::span<const std::byte> block, std::size_t index) {
                        const auto previous = index == 0 ? std::span<const std::byte>{iv_} :
                            data.subspan((index - 1) * block_size, block_size);
                        const auto gamma = cipher.EncryptBlock(previous);
                        ValidateOutputBlockSize(gamma, block_size, "cfb");
                        return XORBlocks(block, gamma);
                    }
                );

                return RemovePadding(result, block_size, padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class OFBMode final : public CipherModeStrategy {
        private:
            [[nodiscard]]
            std::vector<std::byte> TransformBlocks(const SymmetricCipher& cipher, std::span<const std::byte> data) const {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "ofb");
                ValidateIVSize(iv_, block_size, "ofb");

                std::vector<std::byte> result;
                result.reserve(data.size());

                auto gamma = iv_;

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    gamma = cipher.EncryptBlock(gamma);
                    ValidateOutputBlockSize(gamma, block_size, "ofb");
                    const auto block = std::span{data.data() + offset, block_size};
                    const auto new_block = XORBlocks(block, gamma);
                    AppendBlock(result, new_block);
                }

                return result;
            }

        public:
            ~OFBMode() override = default;

            explicit OFBMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                const auto padded = AddPadding(data, block_size, padding_mode);
                return TransformBlocks(cipher, padded);
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto decrypted = TransformBlocks(cipher, data);
                return RemovePadding(decrypted, cipher.BlockSize(), padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class CTRMode final : public CipherModeStrategy {
        private:
            [[nodiscard]]
            std::vector<std::byte> TransformBlocks(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data
            ) const {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "ctr");
                ValidateIVSize(iv_, block_size, "ctr");

                return ProcessBlocksParallel(
                    data,
                    block_size,
                    "ctr",
                    [&](std::span<const std::byte> block, std::size_t index) {
                        const auto counter_block = MakeCounterBlock(iv_, index);
                        const auto gamma = cipher.EncryptBlock(counter_block);
                        ValidateOutputBlockSize(gamma, block_size, "ctr");

                        return XORBlocks(block, gamma);
                    }
                );
            }

        public:
            ~CTRMode() override = default;

            explicit CTRMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                const auto padded = AddPadding(data, block_size, padding_mode);
                return TransformBlocks(cipher, padded);
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto decrypted = TransformBlocks(cipher, data);
                return RemovePadding(decrypted, cipher.BlockSize(), padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class RandomDeltaMode final : public CipherModeStrategy {
        private:
            [[nodiscard]]
            std::vector<std::byte> TransformBlocks(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data
            ) const {
                const auto block_size = cipher.BlockSize();

                ValidateBlockAlignedData(data, block_size, "random delta");
                ValidateIVSize(iv_, block_size, "random delta");

                if (block_size & 1) {
                    throw std::invalid_argument("random delta requires even block size");
                }

                const auto delta = delta_.empty() ?
                    std::vector(iv_.begin() + static_cast<std::ptrdiff_t>(block_size >> 1), iv_.end()) : delta_;
                if (delta.size() != block_size / 2 ||
                    std::ranges::all_of(delta, [](std::byte value) { return value == std::byte{0}; })) {
                    throw std::invalid_argument("random delta requires a nonzero half-block delta");
                }

                return ProcessBlocksParallel(
                    data,
                    block_size,
                    "random delta",
                    [&](std::span<const std::byte> block, std::size_t block_index) {
                        const auto state = MakeRandomDeltaState(iv_, delta, block_index);
                        const auto gamma = cipher.EncryptBlock(state);
                        ValidateOutputBlockSize(gamma, block_size, "random delta");

                        return XORBlocks(block, gamma);
                  }
              );
            }

        public:
            ~RandomDeltaMode() override = default;

            explicit RandomDeltaMode(std::span<const std::byte> iv, std::span<const std::byte> delta = {})
                : iv_(iv.begin(), iv.end()), delta_(delta.begin(), delta.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                const auto padded = AddPadding(data, block_size, padding_mode);
                return TransformBlocks(cipher, padded);
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto decrypted = TransformBlocks(cipher, data);
                return RemovePadding(decrypted, cipher.BlockSize(), padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
            std::vector<std::byte> delta_;
        };
    }

    CipherModeStrategy::~CipherModeStrategy() = default;

    namespace {
        void ValidateNoIV(std::span<const std::byte> iv, std::string_view mode_name) {
            if (!iv.empty()) {
                throw std::invalid_argument(std::format("{} mode does not use IV", mode_name));
            }
        }

        void ValidateNoExtraParameters(
            const std::vector<std::vector<std::byte>>& extra_parameters,
            std::string_view mode_name
        ) {
            if (!extra_parameters.empty()) {
                throw std::invalid_argument(std::format("{} mode does not support extra parameters", mode_name));
            }
        }
    }

    std::unique_ptr<CipherModeStrategy> MakeCipherModeStrategy(
        CipherMode cipher_mode,
        std::span<const std::byte> iv,
        const std::vector<std::vector<std::byte>>& extra_parameters
    ) {
        switch (cipher_mode) {
            case CipherMode::ECB:
                ValidateNoIV(iv, "ecb");
                ValidateNoExtraParameters(extra_parameters, "ecb");
                return std::make_unique<ECBMode>();
            case CipherMode::CBC:
                ValidateNoExtraParameters(extra_parameters, "cbc");
                return std::make_unique<CBCMode>(iv);
            case CipherMode::PCBC:
                ValidateNoExtraParameters(extra_parameters, "pcbc");
                return std::make_unique<PCBCMode>(iv);
            case CipherMode::CFB:
                ValidateNoExtraParameters(extra_parameters, "cfb");
                return std::make_unique<CFBMode>(iv);
            case CipherMode::OFB:
                ValidateNoExtraParameters(extra_parameters, "ofb");
                return std::make_unique<OFBMode>(iv);
            case CipherMode::CTR:
                ValidateNoExtraParameters(extra_parameters, "ctr");
                return std::make_unique<CTRMode>(iv);
            case CipherMode::RandomDelta:
                if (extra_parameters.size() > 1 ||
                    (!extra_parameters.empty() && extra_parameters.front().empty())) {
                    throw std::invalid_argument("random delta accepts one nonempty delta parameter");
                }
                return std::make_unique<RandomDeltaMode>(iv,
                    extra_parameters.empty() ? std::span<const std::byte>{} : extra_parameters.front());
        }

        throw std::invalid_argument("invalid cipher mode");
    }
}
