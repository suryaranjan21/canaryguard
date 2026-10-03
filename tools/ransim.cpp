// SPDX-License-Identifier: GPL-2.0-only
//
// ransim - a HARMLESS imitation of ransomware, for demos and tests only.
//
//   ransim --setup  <folder>              create a demo folder with 20 sample files
//   ransim --attack <folder> [--order alpha|reverse|random] [--delay-ms N]
//   ransim --restore <folder>             undo the attack
//   ransim --snoop  <file> [--times N]    just read a file N times (honeytoken test)
//
// What it does, per file, exactly like real ransomware:
//   1. read the file                  2. scramble the bytes
//   3. overwrite the file             4. rename it to <name>.locked
//
// Why it is safe:
//   * it only works in a folder that contains the marker file
//     (.canaryguard-demo) created by --setup, never anywhere else
//   * the "encryption" is a simple XOR with a fixed key: running it a second
//     time (--restore) brings every file back byte for byte
#include "sandbox.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

namespace fs = std::filesystem;

void scramble(std::string& data) {
    static const char key[] = "CANARYGUARD-DEMO-KEY";
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>(data[i] ^ key[i % (sizeof(key) - 1)]);
}

bool readAll(const fs::path& path, std::string& out) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char chunk[8192];
    out.clear();
    ssize_t n;
    while ((n = ::read(fd, chunk, sizeof(chunk))) > 0) out.append(chunk, static_cast<size_t>(n));
    ::close(fd);
    return n == 0;
}

// Overwrite the file with 'data'. Returns 0 or the errno of the failure.
int overwrite(const fs::path& path, const std::string& data) {
    int fd = ::open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) return errno;
    size_t done = 0;
    while (done < data.size()) {
        ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0) {
            int err = errno;
            ::close(fd);
            return err;
        }
        done += static_cast<size_t>(n);
    }
    ::close(fd);
    return 0;
}

void requireSandbox(const fs::path& dir) {
    if (!sandbox::isSandbox(dir))
        throw std::runtime_error("refusing to touch '" + dir.string() +
                                 "': it is not a demo folder (no " + sandbox::kMarker + " file). "
                                 "Create one with: ransim --setup <folder>");
}

int attack(const fs::path& dir, sandbox::Order order, int delayMs) {
    requireSandbox(dir);
    auto files = sandbox::targets(dir, order);

    std::cout << "ransim (harmless demo): encrypting " << files.size() << " files in " << dir.string() << "\n"
              << std::flush;
    size_t done = 0, blocked = 0, index = 0;
    for (const fs::path& file : files) {
        ++index;
        // Printed BEFORE the work and ended with a newline, so if the kernel
        // kills us right now, the last line shows which file we were attacking.
        char counter[32];
        std::snprintf(counter, sizeof(counter), "  [%2zu/%zu] ", index, files.size());
        std::cout << counter << "encrypting " << file.filename().string() << std::endl;

        std::string data;
        if (!readAll(file, data)) {
            std::cout << "          cannot read, skipped\n";
            continue;
        }
        scramble(data);
        if (int err = overwrite(file, data)) {
            std::cout << "          BLOCKED (" << std::strerror(err) << ")\n";
            ++blocked;
            continue;
        }
        fs::path locked = file;
        locked += sandbox::kLockedSuffix;
        if (::rename(file.c_str(), locked.c_str()) != 0) {
            std::cout << "          rename blocked (" << std::strerror(errno) << ")\n";
            ++blocked;
            continue;
        }
        ++done;
        if (delayMs > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    }

    std::ofstream(dir / sandbox::kRansomNote)
        << "(simulated) Your files have been encrypted by ransim.\n"
           "This is only a demo. Run: ransim --restore <folder>\n";

    std::cout << "ransim finished: " << done << " files encrypted, " << blocked << " blocked. "
              << "Nothing stopped it.\n";
    return 0;
}

int restore(const fs::path& dir) {
    requireSandbox(dir);
    auto files = sandbox::targets(dir, sandbox::Order::Alpha, true);
    size_t done = 0;
    for (const fs::path& locked : files) {
        std::string data;
        if (!readAll(locked, data)) continue;
        scramble(data);                                     // XOR twice = the original
        if (overwrite(locked, data) != 0) continue;
        fs::path original = locked;
        original.replace_extension("");                     // drop ".locked"
        if (::rename(locked.c_str(), original.c_str()) == 0) ++done;
    }
    std::error_code ec;
    fs::remove(dir / sandbox::kRansomNote, ec);
    std::cout << "ransim: restored " << done << " files in " << dir.string() << "\n";
    return 0;
}

// Open and close a file N times, as a snooping program would.
int snoop(const std::string& file, int times) {
    for (int i = 0; i < times; ++i) {
        int fd = ::open(file.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            std::cerr << "ransim: cannot open " << file << ": " << std::strerror(errno) << "\n";
            return 1;
        }
        ::close(fd);
    }
    return 0;
}

void usage() {
    std::cout << "ransim - harmless ransomware imitation (demos and tests only)\n\n"
                 "  ransim --setup   <folder>\n"
                 "  ransim --attack  <folder> [--order alpha|reverse|random] [--delay-ms N]\n"
                 "  ransim --restore <folder>\n"
                 "  ransim --snoop   <file> [--times N]\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        usage();
        return 1;
    }
    std::string mode = argv[1];
    std::string target = argv[2];
    sandbox::Order order = sandbox::Order::Alpha;
    int delayMs = 0, times = 1;

    try {
        for (int i = 3; i < argc; ++i) {
            std::string opt = argv[i];
            auto value = [&]() -> std::string {
                if (i + 1 >= argc) throw std::runtime_error("missing value after " + opt);
                return argv[++i];
            };
            if (opt == "--order") {
                std::string v = value();
                if (v == "alpha") order = sandbox::Order::Alpha;
                else if (v == "reverse") order = sandbox::Order::Reverse;
                else if (v == "random") order = sandbox::Order::Random;
                else throw std::runtime_error("unknown order: " + v);
            } else if (opt == "--delay-ms") {
                delayMs = std::stoi(value());
            } else if (opt == "--times") {
                times = std::stoi(value());
            } else {
                throw std::runtime_error("unknown option: " + opt);
            }
        }

        if (mode == "--setup") {
            sandbox::setup(target);
            std::cout << "ransim: demo folder ready: " << target << "\n";
            return 0;
        }
        if (mode == "--attack") return attack(target, order, delayMs);
        if (mode == "--restore") return restore(target);
        if (mode == "--snoop") return snoop(target, times);

        usage();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "ransim: " << e.what() << "\n";
        return 1;
    }
}
