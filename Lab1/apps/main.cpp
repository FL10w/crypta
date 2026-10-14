import std;
import crypto.context;
import crypto.cipher;
import crypto.padding;
import crypto.modes;
import crypto.des;
import crypto.deal;

namespace {
    constexpr std::array mode_names{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"};
    constexpr std::array padding_names{"Zeros", "ANSIX923", "PKCS7", "ISO10126"};

    std::vector<std::byte> RandomBytes(std::size_t size) {
        std::random_device device;
        std::mt19937_64 generator(device());
        std::uniform_int_distribution<unsigned> distribution(0, 255);
        std::vector<std::byte> result(size);
        for (auto& byte : result) byte = static_cast<std::byte>(distribution(generator));
        return result;
    }

    std::vector<std::byte> ReadFile(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file || file.tellg() < 0) throw std::runtime_error("Cannot open " + path.string());
        std::vector<std::byte> data(static_cast<std::size_t>(file.tellg()));
        file.seekg(0);
        if (!data.empty() && !file.read(reinterpret_cast<char*>(data.data()), data.size()))
            throw std::runtime_error("Cannot read " + path.string());
        return data;
    }

    void DemoAlgorithm(std::string_view name, std::size_t key_size,
        const std::vector<std::filesystem::path>& files, const std::filesystem::path& output,
        std::size_t& total) {
        const auto key = RandomBytes(key_size);
        auto iv = RandomBytes(name == "DES" ? 8 : 16);
        iv.back() |= std::byte{1};
        auto random = RandomBytes(5251);
        random.insert(random.end(), 4, std::byte{0});
        const std::array inputs{std::vector<std::byte>{}, std::vector(32, std::byte{0}), random};
        for (int mode = 0; mode < 7; ++mode) {
            for (int padding = 0; padding < 4; ++padding) {
                std::unique_ptr<crypto::SymmetricCipher> cipher;
                if (name == "DES") cipher = std::make_unique<crypto::DES>();
                else cipher = std::make_unique<crypto::DEAL>();
                const crypto::SymmetricCipherContext context(std::move(cipher), key,
                    static_cast<crypto::CipherMode>(mode), static_cast<crypto::PaddingMode>(padding),
                    mode == 0 ? std::span<const std::byte>{} : iv);
                for (const auto& input : inputs) {
                    std::vector<std::byte> encrypted, decrypted;
                    context.EncryptAsync(input, encrypted).get();
                    context.DecryptAsync(encrypted, decrypted).get();
                    if (input != decrypted) throw std::runtime_error("Memory roundtrip mismatch");
                    ++total;
                }
                const auto directory = output / name / mode_names[mode] / padding_names[padding];
                std::filesystem::create_directories(directory);
                for (std::size_t i = 0; i < files.size(); ++i) {
                    const auto& input = files[i];
                    const auto stem = std::to_string(i) + "_" + input.filename().string();
                    const auto encrypted = directory / (stem + ".encrypted");
                    const auto restored = directory / (stem + ".restored");
                    context.EncryptAsync(input, encrypted).get();
                    context.DecryptAsync(encrypted, restored).get();
                    if (ReadFile(input) != ReadFile(restored))
                        throw std::runtime_error("File roundtrip mismatch: " + input.string());
                    ++total;
                }
                std::cout << "[OK] " << name << ' ' << mode_names[mode] << ' '
                    << padding_names[padding] << ": 3 memory samples, " << files.size() << " files\n";
            }
        }
    }
}

int main(int argc, char** argv) {
    try {
        auto assets = std::filesystem::absolute(argv[0]).parent_path() / "demo/assets";
        auto output = std::filesystem::absolute(argv[0]).parent_path() / "demo/results";
        std::vector<std::filesystem::path> files;
        for (int i = 1; i < argc; ++i) {
            const std::string_view argument = argv[i];
            if (argument == "--help") {
                std::cout << "crypto [--assets DIR] [--output DIR] [--file PATH ...]\n"
                    << "Tests DES and DEAL-128/192/256 in all modes and paddings.\n";
                return 0;
            }
            if (i + 1 == argc) throw std::invalid_argument("Missing value for " + std::string(argument));
            if (argument == "--assets") assets = argv[++i];
            else if (argument == "--output") output = argv[++i];
            else if (argument == "--file") files.emplace_back(argv[++i]);
            else throw std::invalid_argument("Unknown option: " + std::string(argument));
        }
        if (files.empty()) {
            for (const auto& file : std::filesystem::directory_iterator(assets)) {
                if (file.is_regular_file()) files.push_back(file.path());
            }
            std::ranges::sort(files);
        }
        if (files.empty()) throw std::invalid_argument("No demonstration files found");
        output = std::filesystem::absolute(output).lexically_normal();
        for (auto& file : files) {
            file = std::filesystem::absolute(file).lexically_normal();
            // Outputs must never overlap the input tree, including reruns.
            const auto relative = file.lexically_relative(output);
            if (relative.empty() || *relative.begin() != "..")
                throw std::invalid_argument("Input files must be outside the output directory");
            ReadFile(file);
            std::cout << "Input: " << file.string() << '\n';
        }
        std::size_t total = 0;
        DemoAlgorithm("DES", 8, files, output, total);
        DemoAlgorithm("DEAL-128", 16, files, output, total);
        DemoAlgorithm("DEAL-192", 24, files, output, total);
        DemoAlgorithm("DEAL-256", 32, files, output, total);
        std::cout << "All " << total << " roundtrips passed.\nResults: " << output.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Demo failed: " << error.what() << '\n';
        return 1;
    }
}
