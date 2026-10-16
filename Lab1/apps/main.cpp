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
    constexpr std::array algorithm_names{"DES", "DEAL-128", "DEAL-192", "DEAL-256"};
    constexpr std::array<std::size_t, 4> key_sizes{8, 16, 24, 32};

    template<std::size_t N>
    int Choice(std::string_view value, const std::array<const char*, N>& names, std::string_view option) {
        for (std::size_t i = 0; i < N; ++i) {
            if (value == names[i]) return static_cast<int>(i);
        }
        throw std::invalid_argument("Invalid value for " + std::string(option) + ": " + std::string(value));
    }

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
        std::size_t& total, std::size_t& skipped,
        int selected_mode, int selected_padding, bool show_timings) {
        const auto key = RandomBytes(key_size);
        auto iv = RandomBytes(name == "DES" ? 8 : 16);
        iv.back() |= std::byte{1};
        auto random = RandomBytes(5251);
        random.push_back(std::byte{1});
        auto zero_prefix = std::vector(32, std::byte{0});
        zero_prefix.back() = std::byte{1};
        const std::array inputs{std::vector{std::byte{1}}, zero_prefix, random};
        for (int mode = 0; mode < 7; ++mode) {
            if (selected_mode != -1 && selected_mode != mode) continue;
            for (int padding = 0; padding < 4; ++padding) {
                if (selected_padding != -1 && selected_padding != padding) continue;
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
                std::size_t checked_files = 0;
                for (std::size_t i = 0; i < files.size(); ++i) {
                    const auto& input = files[i];
                    const auto stem = std::to_string(i) + "_" + input.filename().string();
                    const auto encrypted = directory / (stem + ".encrypted");
                    const auto restored = directory / (stem + ".restored");
                    const auto original = ReadFile(input);
                    if (padding == 0 && (original.empty() || original.back() == std::byte{0})) {
                        // Zeros cannot distinguish original trailing zeros from padding.
                        // Discard stale outputs from older runs of this demonstration.
                        std::filesystem::remove(encrypted);
                        std::filesystem::remove(restored);
                        ++skipped;
                        std::cout << "[SKIP] " << name << ' ' << mode_names[mode] << " Zeros "
                            << input.filename().string()
                            << ": exact roundtrip requires nonempty input ending in a nonzero byte"
                            << std::endl;
                        continue;
                    }
                    const auto start = std::chrono::steady_clock::now();
                    context.EncryptAsync(input, encrypted).get();
                    const auto encrypted_at = std::chrono::steady_clock::now();
                    context.DecryptAsync(encrypted, restored).get();
                    const auto restored_at = std::chrono::steady_clock::now();
                    if (original != ReadFile(restored))
                        throw std::runtime_error("File roundtrip mismatch: " + input.string());
                    ++total;
                    ++checked_files;
                    if (show_timings) {
                        std::cout << "[FILE OK] " << name << ' ' << mode_names[mode] << ' '
                            << padding_names[padding] << ' ' << input.filename().string()
                            << std::fixed << std::setprecision(3)
                            << " encrypt=" << std::chrono::duration<double>(encrypted_at - start).count()
                            << "s decrypt=" << std::chrono::duration<double>(restored_at - encrypted_at).count()
                            << "s" << std::endl;
                    }
                }
                std::cout << "[OK] " << name << ' ' << mode_names[mode] << ' '
                    << padding_names[padding] << ": 3 memory samples, " << checked_files << " files" << std::endl;
            }
        }
    }
}

int main(int argc, char** argv) {
    try {
        auto assets = std::filesystem::absolute(argv[0]).parent_path() / "demo/assets";
        auto output = std::filesystem::absolute(argv[0]).parent_path() / "demo/results";
        std::vector<std::filesystem::path> files;
        int selected_algorithm = -1, selected_mode = -1, selected_padding = -1;
        for (int i = 1; i < argc; ++i) {
            const std::string_view argument = argv[i];
            if (argument == "--help") {
                std::cout << "crypto [--assets DIR] [--output DIR] [--file PATH ...]\n"
                    << "       [--algorithm DES|DEAL-128|DEAL-192|DEAL-256]\n"
                    << "       [--mode ECB|CBC|PCBC|CFB|OFB|CTR|RandomDelta]\n"
                    << "       [--padding Zeros|ANSIX923|PKCS7|ISO10126]\n"
                    << "Unspecified filters select all values. Explicit files include operation timings.\n";
                return 0;
            }
            if (i + 1 == argc) throw std::invalid_argument("Missing value for " + std::string(argument));
            if (argument == "--assets") assets = argv[++i];
            else if (argument == "--output") output = argv[++i];
            else if (argument == "--file") files.emplace_back(argv[++i]);
            else if (argument == "--algorithm") selected_algorithm = Choice(argv[++i], algorithm_names, argument);
            else if (argument == "--mode") selected_mode = Choice(argv[++i], mode_names, argument);
            else if (argument == "--padding") selected_padding = Choice(argv[++i], padding_names, argument);
            else throw std::invalid_argument("Unknown option: " + std::string(argument));
        }
        const bool show_timings = !files.empty();
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
        std::size_t total = 0, skipped = 0;
        for (std::size_t algorithm = 0; algorithm < algorithm_names.size(); ++algorithm) {
            if (selected_algorithm != -1 && selected_algorithm != static_cast<int>(algorithm)) continue;
            DemoAlgorithm(algorithm_names[algorithm], key_sizes[algorithm], files, output, total, skipped,
                selected_mode, selected_padding, show_timings);
        }
        std::cout << "All " << total << " roundtrips passed.\n";
        if (skipped) std::cout << "Skipped " << skipped << " file checks due to Zeros padding limitations.\n";
        std::cout << "Results: " << output.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Demo failed: " << error.what() << '\n';
        return 1;
    }
}
