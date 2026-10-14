export module crypto.padding;

import std;

export namespace crypto {
    enum class PaddingMode {
        Zeros = 0,
        ANSIX923 = 1,
        PKCS7 = 2,
        ISO10126 = 3,
    };

    std::vector<std::byte> AddPadding(
        std::span<const std::byte> data,
        std::size_t                block_size,
        PaddingMode                padding_mode
    );

    std::vector<std::byte> RemovePadding(
        std::span<const std::byte> data,
        std::size_t                block_size,
        PaddingMode                padding_mode
    );
}
