module crypto.padding;

import std;

namespace crypto {
    namespace {
        void ValidateBlockSize(
            std::size_t block_size,
            std::string_view padding_name,
            bool require_byte_sized_block_size
        ) {
            if (block_size == 0 || (require_byte_sized_block_size && block_size > 255)) {
                throw std::invalid_argument(
                    std::format("block size for {} padding is invalid", padding_name)
                );
            }
        }

        void ValidatePaddedData(
            std::span<const std::byte> data,
            std::size_t block_size,
            std::string_view padding_name,
            bool require_byte_sized_block_size
        ) {
            ValidateBlockSize(block_size, padding_name, require_byte_sized_block_size);

            if (data.empty() || data.size() % block_size != 0) {
                throw std::invalid_argument(
                    std::format("data size for {} padding is invalid", padding_name)
                );
            }
        }

        std::vector<std::byte> AddZerosPadding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidateBlockSize(block_size, "zeros", false);

            std::vector padded(data.begin(), data.end());

            const std::size_t remainder = padded.size() % block_size;
            if (remainder == 0) {
                return padded;
            }

            const std::size_t padding_size = block_size - remainder;
            padded.insert(padded.end(), padding_size, std::byte{0});

            return padded;
        }

        std::size_t PaddingSize(std::size_t data_size, std::size_t block_size) {
            const std::size_t remainder = data_size % block_size;
            return remainder == 0 ? block_size : block_size - remainder;
        }

        std::vector<std::byte> AddANSIX923Padding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidateBlockSize(block_size, "ansix923", true);

            std::vector padded(data.begin(), data.end());

            const std::size_t padding_size = PaddingSize(data.size(), block_size);
            padded.insert(padded.end(), padding_size - 1, std::byte{0});
            padded.insert(padded.end(), 1, static_cast<std::byte>(padding_size));

            return padded;
        }

        std::vector<std::byte> AddPKCS7Padding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidateBlockSize(block_size, "pkcs7", true);

            std::vector padded(data.begin(), data.end());

            const std::size_t padding_size = PaddingSize(data.size(), block_size);
            padded.insert(padded.end(), padding_size, static_cast<std::byte>(padding_size));

            return padded;
        }

        std::vector<std::byte> AddISO10126Padding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidateBlockSize(block_size, "iso10126", true);

            std::vector padded(data.begin(), data.end());

            const std::size_t padding_size = PaddingSize(data.size(), block_size);
            padded.reserve(data.size() + padding_size);

            std::random_device device;
            std::mt19937_64 generator(device());
            std::uniform_int_distribution distribution(0, 255);

            for (std::size_t i = 0; i < padding_size - 1; ++i) {
                padded.emplace_back(static_cast<std::byte>(distribution(generator)));
            }
            padded.emplace_back(static_cast<std::byte>(padding_size));

            return padded;
        }

        std::vector<std::byte> RemoveZerosPadding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidatePaddedData(data, block_size, "zeros", false);

            std::vector unpadded(data.begin(), data.end());
            while (!unpadded.empty() && unpadded.back() == std::byte{0}) {
                unpadded.pop_back();
            }

            if (unpadded.empty()) {
                unpadded.push_back(std::byte{0});
            }

            return unpadded;
        }

        std::size_t GetPaddingSize(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            const auto padding_size = static_cast<std::size_t>(data.back());
            if (padding_size == 0 || padding_size > block_size || padding_size > data.size()) {
                throw std::invalid_argument("invalid data padding size");
            }

            return padding_size;
        }

        std::vector<std::byte> RemoveANSIX923Padding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidatePaddedData(data, block_size, "ansix923", true);

            const auto padding_size = GetPaddingSize(data, block_size);
            const auto padding_begin = data.end() - static_cast<std::ptrdiff_t>(padding_size);

            const bool is_valid = std::all_of(
                padding_begin,
                data.end() - 1,
                [](std::byte value) { return value == std::byte{0}; }
            );

            if (!is_valid) {
                throw std::invalid_argument("invalid ansix923 padding");
            }

            std::vector unpadded(data.begin(), data.end() - static_cast<std::ptrdiff_t>(padding_size));

            return unpadded;
        }

        std::vector<std::byte> RemovePKCS7Padding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidatePaddedData(data, block_size, "pkcs7", true);

            const auto padding_size = GetPaddingSize(data, block_size);
            const auto padding_begin = data.end() - static_cast<std::ptrdiff_t>(padding_size);

            const bool is_valid = std::all_of(
                padding_begin,
                data.end(),
                [padding_size](std::byte value) { return value == static_cast<std::byte>(padding_size); }
            );

            if (!is_valid) {
                throw std::invalid_argument("invalid pkcs7 padding");
            }

            std::vector unpadded(data.begin(), data.end() - static_cast<std::ptrdiff_t>(padding_size));

            return unpadded;
        }

        std::vector<std::byte> RemoveISO10126Padding(
            std::span<const std::byte> data,
            std::size_t block_size
        ) {
            ValidatePaddedData(data, block_size, "iso10126", true);

            const auto padding_size = GetPaddingSize(data, block_size);

            std::vector unpadded(data.begin(), data.end() - static_cast<std::ptrdiff_t>(padding_size));

            return unpadded;
        }
    }

    std::vector<std::byte> AddPadding(
        std::span<const std::byte> data,
        std::size_t block_size,
        PaddingMode padding_mode
    ) {
        switch (padding_mode) {
            case PaddingMode::Zeros:
                return AddZerosPadding(data, block_size);
            case PaddingMode::ANSIX923:
                return AddANSIX923Padding(data, block_size);
            case PaddingMode::PKCS7:
                return AddPKCS7Padding(data, block_size);
            case PaddingMode::ISO10126:
                return AddISO10126Padding(data, block_size);
        }

        throw std::invalid_argument("unknown padding mode");
    }

    std::vector<std::byte> RemovePadding(
        std::span<const std::byte> data,
        std::size_t                block_size,
        PaddingMode                padding_mode
    ) {
        switch (padding_mode) {
            case PaddingMode::Zeros:
                return RemoveZerosPadding(data, block_size);
            case PaddingMode::ANSIX923:
                return RemoveANSIX923Padding(data, block_size);
            case PaddingMode::PKCS7:
                return RemovePKCS7Padding(data, block_size);
            case PaddingMode::ISO10126:
                return RemoveISO10126Padding(data, block_size);
        }

        throw std::invalid_argument("unknown padding mode");
    }
}
