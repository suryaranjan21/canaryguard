// SPDX-License-Identifier: GPL-2.0-only
//
// sandbox.hpp - the demo "playground" shared by ransim and cgdemo.
//
// A sandbox is an ordinary folder that contains a marker file plus 20 sample
// documents. The fake ransomware (ransim) refuses to touch any folder that
// does not carry the marker, so it can never harm real data.
#pragma once

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace sandbox {

namespace fs = std::filesystem;

constexpr const char* kRoot = "/var/tmp/canaryguard-demo";
constexpr const char* kMarker = ".canaryguard-demo";
constexpr const char* kLockedSuffix = ".locked";
constexpr const char* kRansomNote = "READ_ME_TO_RESTORE_FILES.txt";

// Case-insensitively sorted, exactly three of these come before the canary
// "Budget_2026.xlsx", which makes the demo tell a clear story.
inline const std::vector<std::string>& sampleNames() {
    static const std::vector<std::string> names = {
        "Agreement_Rent.docx",    "Agreement_Vehicle.docx", "Appraisal_Letter.pdf",
        "Certificates_Scan.pdf",  "Contract_Offer.pdf",     "Course_Notes_Linux.txt",
        "Diary_2026.docx",        "Exam_Timetable.xlsx",    "Holiday_Photo_01.jpg",
        "Holiday_Photo_02.jpg",   "Holiday_Photo_03.jpg",   "Insurance_Policy.pdf",
        "Invoice_Laptop.pdf",     "Medical_Report.pdf",     "Project_Report.docx",
        "Resume_Final.docx",      "Salary_Slips.zip",       "Semester_Marks.xlsx",
        "Thesis_Draft.docx",      "Wedding_Video_Clip.mp4",
    };
    return names;
}

inline std::string sampleContent(const std::string& name) {
    std::string body;
    while (body.size() < 4096)
        body += "This is the precious content of " + name + ". It must not be lost!\n";
    return body;
}

inline bool isSandbox(const fs::path& dir) { return fs::exists(dir / kMarker); }

// Create the folder, the marker and the sample files. Refuses to use a folder
// that already has other content (so it can never clutter a real folder).
// Files are given to 'uid'/'gid' unless those are (uid_t)-1.
inline void setup(const fs::path& dir, uid_t uid = static_cast<uid_t>(-1), gid_t gid = static_cast<gid_t>(-1)) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) throw std::runtime_error("cannot create " + dir.string() + ": " + ec.message());
    if (!isSandbox(dir) && !fs::is_empty(dir))
        throw std::runtime_error(dir.string() + " is not empty and not a demo folder: refusing to use it");

    auto give = [&](const fs::path& p) {
        if (uid != static_cast<uid_t>(-1)) { if (::chown(p.c_str(), uid, gid) != 0) { /* best effort */ } }
    };

    std::ofstream(dir / kMarker) << "CanaryGuard demo sandbox: ransim may only touch folders with this file.\n";
    give(dir / kMarker);
    for (const std::string& name : sampleNames()) {
        std::ofstream(dir / name, std::ios::binary) << sampleContent(name);
        give(dir / name);
    }
    give(dir);
}

enum class Order { Alpha, Reverse, Random };

// The regular files an attacker would go after (not the marker or the note).
// With lockedOnly the already-encrypted "*.locked" files are returned instead.
inline std::vector<fs::path> targets(const fs::path& dir, Order order, bool lockedOnly = false) {
    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        std::string name = entry.path().filename().string();
        if (name == kMarker || name == kRansomNote) continue;
        bool locked = name.size() > std::string(kLockedSuffix).size() &&
                      name.compare(name.size() - std::string(kLockedSuffix).size(), std::string::npos, kLockedSuffix) == 0;
        if (locked != lockedOnly) continue;
        files.push_back(entry.path());
    }
    auto lower = [](std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    };
    std::sort(files.begin(), files.end(),
              [&](const fs::path& a, const fs::path& b) { return lower(a.filename().string()) < lower(b.filename().string()); });
    if (order == Order::Reverse) std::reverse(files.begin(), files.end());
    if (order == Order::Random) std::shuffle(files.begin(), files.end(), std::mt19937(std::random_device{}()));
    return files;
}

inline size_t countLocked(const fs::path& dir) {
    size_t n = 0;
    for (const auto& entry : fs::directory_iterator(dir))
        if (entry.is_regular_file() && entry.path().extension() == kLockedSuffix) ++n;
    return n;
}

}  // namespace sandbox
