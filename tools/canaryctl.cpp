// SPDX-License-Identifier: GPL-2.0-only
//
// canaryctl - the control panel for the CanaryGuard driver.
//
//   canaryctl plant <folder>      guard a folder: bait files + speed check
//   canaryctl watch <folder>      speed check only, no bait files
//   canaryctl list                show everything that is registered
//   canaryctl stats               counters and current settings
//   canaryctl mode kill|warn      block+kill attackers, or only alert
//   canaryctl speed <files> <ms>  speed limit, e.g. "speed 10 2000"
//   canaryctl speed on|off
//   canaryctl allow <name>        never block/kill this process name
//   canaryctl disallow <name>
//   canaryctl allowed             list the safe names
//   canaryctl remove <id>         stop guarding one item
//   canaryctl clear               stop guarding everything
//   canaryctl reset               set the counters back to zero
//
// Every command talks to the kernel driver through /dev/canaryguard.
#include "cg_common.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// ---------------------------------------------------------------------------
// The bait. Names look valuable to a thief; the content is junk or obviously
// fake (the AWS keys are the examples from Amazon's own documentation).
// ---------------------------------------------------------------------------

struct Bait {
    const char* name;
    uint32_t kind;
};

const Bait kBait[] = {
    {"Budget_2026.xlsx", CG_KIND_CANARY},
    {"Family_Photos_Backup.zip", CG_KIND_CANARY},
    {"Tax_Returns_2025.pdf", CG_KIND_CANARY},
    {"passwords.txt", CG_KIND_HONEYTOKEN},
    {"server_login_backup.txt", CG_KIND_HONEYTOKEN},
};

bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string canaryBody(const std::string& name) {
    std::string body;
    if (endsWith(name, ".xlsx") || endsWith(name, ".zip"))
        body.assign("PK\x03\x04", 4);               // looks like a zip container
    else if (endsWith(name, ".pdf"))
        body = "%PDF-1.4\n";

    uint32_t x = 2166136261u;                       // seed from the name: stable content
    for (char c : name) x = (x ^ static_cast<unsigned char>(c)) * 16777619u;
    while (body.size() < 8192) {
        x = x * 1664525u + 1013904223u;
        body.push_back(static_cast<char>('a' + (x >> 24) % 26));
        if ((x >> 16) % 7 == 0) body.push_back(' ');
        if ((x >> 8) % 61 == 0) body.push_back('\n');
    }
    return body;
}

std::string honeytokenBody(const std::string& name) {
    if (name == "passwords.txt")
        return "My passwords (do not share!)\n"
               "----------------------------\n"
               "Gmail        student.demo@example.com     Summer#2026!\n"
               "Net banking  demo_user_4821               Blue$Horse9\n"
               "Wi-Fi        HomeNetwork_5G               kP9#mQ2$vL\n";
    return "# server login backup\n"
           "aws_access_key_id     = AKIAIOSFODNN7EXAMPLE\n"
           "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
           "ssh root@10.0.0.12    password: Tr0ub4dor&3\n";
}

// Create the file only if it does not exist yet: we never overwrite real data.
bool createBaitFile(const fs::path& path, const std::string& body, uid_t uid, gid_t gid) {
    cg::Fd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644));
    if (!fd) {
        if (errno == EEXIST) return false;
        throw cg::Error(cg::errnoText("cannot create " + path.string(), errno));
    }
    size_t done = 0;
    while (done < body.size()) {
        ssize_t n = ::write(fd.get(), body.data() + done, body.size() - done);
        if (n < 0) throw cg::Error(cg::errnoText("cannot write " + path.string(), errno));
        done += static_cast<size_t>(n);
    }
    // The bait should belong to whoever owns the folder, not to root.
    if (::fchown(fd.get(), uid, gid) != 0) { /* best effort */ }
    return true;
}

fs::path existingDirectory(const std::string& arg) {
    std::error_code ec;
    fs::path dir = fs::canonical(arg, ec);
    if (ec) throw cg::Error("cannot find folder '" + arg + "': " + ec.message());
    if (!fs::is_directory(dir)) throw cg::Error("not a folder: " + dir.string());
    return dir;
}

// Register a folder for the speed check; "already registered" is fine.
void watchFolder(cg::Device& dev, const fs::path& dir) {
    try {
        uint32_t id = dev.add(CG_KIND_WATCHDIR, dir.string());
        std::cout << "  watching folder   " << dir.string() << "   (id " << id << ")\n";
    } catch (const cg::Error& e) {
        if (std::string(e.what()).find("File exists") == std::string::npos) throw;
        std::cout << "  already watching  " << dir.string() << "\n";
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

using Args = std::vector<std::string>;

void need(const Args& a, size_t n, const char* usage) {
    if (a.size() != n) throw cg::Error(std::string("usage: canaryctl ") + usage);
}

int cmdPlant(cg::Device& dev, const Args& a) {
    need(a, 1, "plant <folder>");
    fs::path dir = existingDirectory(a[0]);

    struct stat st{};
    if (::stat(dir.c_str(), &st) != 0) throw cg::Error(cg::errnoText("stat " + dir.string(), errno));

    std::cout << "Planting bait in " << dir.string() << "\n";

    // 1. Create the bait files first, while the folder is not watched yet.
    //    A file that is already there is left exactly as it is, but it is
    //    still registered below: otherwise running 'plant' a second time
    //    would leave the bait sitting there unprotected.
    std::vector<std::pair<fs::path, uint32_t>> bait;
    for (const Bait& b : kBait) {
        fs::path file = dir / b.name;
        std::string body = b.kind == CG_KIND_CANARY ? canaryBody(b.name) : honeytokenBody(b.name);
        bool fresh = createBaitFile(file, body, st.st_uid, st.st_gid);
        if (!fresh) std::cout << "  (" << b.name << " already exists: keeping its contents)\n";
        bait.emplace_back(file, b.kind);
    }

    // 2. ... then tell the driver about the folder and every bait file.
    watchFolder(dev, dir);
    for (const auto& [file, kind] : bait) {
        const char* label = kind == CG_KIND_CANARY ? "canary file" : "honeytoken";
        try {
            uint32_t id = dev.add(kind, file.string());
            std::cout << "  " << std::left << std::setw(17) << label << file.filename().string() << "   (id " << id
                      << ")\n";
        } catch (const cg::Error& e) {
            if (std::string(e.what()).find("File exists") == std::string::npos) throw;
            std::cout << "  " << std::left << std::setw(17) << label << file.filename().string()
                      << "   (already guarded)\n";
        }
    }
    return 0;
}

int cmdWatch(cg::Device& dev, const Args& a) {
    need(a, 1, "watch <folder>");
    watchFolder(dev, existingDirectory(a[0]));
    return 0;
}

int cmdList(cg::Device& dev, const Args& a) {
    need(a, 0, "list");
    auto entries = dev.entries();
    if (entries.empty()) {
        std::cout << "Nothing is registered. Try: sudo canaryctl plant <folder>\n";
        return 0;
    }
    std::cout << std::left << std::setw(5) << "ID" << std::setw(16) << "KIND" << std::setw(7) << "HITS"
              << "PATH\n";
    for (const cg_entry& e : entries)
        std::cout << std::left << std::setw(5) << e.id << std::setw(16) << cg::kindName(e.kind) << std::setw(7)
                  << e.hits << e.path << "\n";
    return 0;
}

int cmdStats(cg::Device& dev, const Args& a) {
    need(a, 0, "stats");
    cg_stats s = dev.stats();
    cg_config c = dev.config();
    std::cout << "Mode              : " << (c.mode == CG_MODE_KILL ? "kill (block + kill attackers)" : "warn (alerts only)")
              << "\n"
              << "Speed check       : " << (c.speed_enabled ? "on" : "off") << ", limit " << c.speed_threshold
              << " files within " << c.speed_window_ms << " ms\n"
              << "Protected items   : " << s.entries << "\n"
              << "Events recorded   : " << s.events << "\n"
              << "Events lost       : " << s.dropped << "  (ring buffer holds " << CG_RING_EVENTS << ")\n"
              << "Operations missed : " << s.missed << "  (kernel had no free probe slot; should be 0)\n"
              << "Processes killed  : " << s.kills << "\n"
              << "  canary hits     : " << s.canary_hits << "\n"
              << "  honeytoken hits : " << s.honeytoken_hits << "\n"
              << "  speed-check hits: " << s.speed_hits << "\n"
              << "Open handles      : " << s.open_handles << "\n";
    return 0;
}

int cmdMode(cg::Device& dev, const Args& a) {
    need(a, 1, "mode kill|warn");
    cg_config c = dev.config();
    if (a[0] == "kill") c.mode = CG_MODE_KILL;
    else if (a[0] == "warn") c.mode = CG_MODE_WARN;
    else throw cg::Error("usage: canaryctl mode kill|warn");
    dev.setConfig(c);
    std::cout << "Mode is now '" << a[0] << "'\n";
    return 0;
}

int cmdSpeed(cg::Device& dev, const Args& a) {
    cg_config c = dev.config();
    if (a.size() == 1 && (a[0] == "on" || a[0] == "off")) {
        c.speed_enabled = a[0] == "on";
    } else if (a.size() == 2) {
        try {
            c.speed_threshold = static_cast<uint32_t>(std::stoul(a[0]));
            c.speed_window_ms = static_cast<uint32_t>(std::stoul(a[1]));
        } catch (const std::exception&) {
            throw cg::Error("usage: canaryctl speed <files> <milliseconds> | on | off");
        }
        c.speed_enabled = 1;
    } else {
        throw cg::Error("usage: canaryctl speed <files> <milliseconds> | on | off");
    }
    dev.setConfig(c);  // the driver checks the ranges
    std::cout << "Speed check " << (c.speed_enabled ? "on" : "off") << ": " << c.speed_threshold << " files within "
              << c.speed_window_ms << " ms\n";
    return 0;
}

int cmdAllow(cg::Device& dev, const Args& a) {
    need(a, 1, "allow <process-name>");
    dev.allow(a[0]);
    std::cout << "'" << a[0] << "' will never be blocked or killed\n";
    return 0;
}

int cmdDisallow(cg::Device& dev, const Args& a) {
    need(a, 1, "disallow <process-name>");
    dev.disallow(a[0]);
    std::cout << "'" << a[0] << "' removed from the safe list\n";
    return 0;
}

int cmdAllowed(cg::Device& dev, const Args& a) {
    need(a, 0, "allowed");
    std::cout << "Safe process names (never blocked or killed):\n";
    for (const std::string& n : dev.allowList()) std::cout << "  " << n << "\n";
    return 0;
}

int cmdRemove(cg::Device& dev, const Args& a) {
    need(a, 1, "remove <id>");
    dev.remove(static_cast<uint32_t>(std::stoul(a[0])));
    std::cout << "Removed entry " << a[0] << " (the file itself is untouched)\n";
    return 0;
}

int cmdReset(cg::Device& dev, const Args& a) {
    need(a, 0, "reset");
    dev.resetStats();
    std::cout << "Counters are back to zero\n";
    return 0;
}

int cmdClear(cg::Device& dev, const Args& a) {
    need(a, 0, "clear");
    dev.clear();
    std::cout << "Nothing is guarded any more (the files themselves are untouched)\n";
    return 0;
}

void usage() {
    std::cout << "canaryctl - control panel for the CanaryGuard driver\n\n"
                 "  plant <folder>        guard a folder: bait files + speed check\n"
                 "  watch <folder>        speed check only, no bait files\n"
                 "  list                  show everything that is registered\n"
                 "  stats                 counters and current settings\n"
                 "  mode kill|warn        block+kill attackers, or only raise alerts\n"
                 "  speed <files> <ms>    speed limit, e.g. 'speed 10 2000'   (also: on | off)\n"
                 "  allow <name>          never block or kill this process name\n"
                 "  disallow <name>       remove a name from the safe list\n"
                 "  allowed               list the safe names\n"
                 "  remove <id>           stop guarding one item\n"
                 "  clear                 stop guarding everything\n"
                 "  reset                 set the counters back to zero\n\n"
                 "Needs root: run with sudo. The driver must be loaded ('sudo make load').\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2 || std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help" ||
        std::string(argv[1]) == "help") {
        usage();
        return argc < 2 ? 1 : 0;
    }

    const std::map<std::string, std::function<int(cg::Device&, const Args&)>> commands = {
        {"plant", cmdPlant}, {"watch", cmdWatch},       {"list", cmdList},   {"stats", cmdStats},
        {"mode", cmdMode},   {"speed", cmdSpeed},       {"allow", cmdAllow}, {"disallow", cmdDisallow},
        {"allowed", cmdAllowed}, {"remove", cmdRemove}, {"clear", cmdClear}, {"reset", cmdReset},
    };

    auto it = commands.find(argv[1]);
    if (it == commands.end()) {
        std::cerr << "canaryctl: unknown command '" << argv[1] << "'\n\n";
        usage();
        return 1;
    }

    try {
        cg::Device dev;
        return it->second(dev, Args(argv + 2, argv + argc));
    } catch (const std::exception& e) {
        std::cerr << "canaryctl: " << e.what() << "\n";
        return 1;
    }
}
