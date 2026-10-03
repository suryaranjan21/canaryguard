// SPDX-License-Identifier: GPL-2.0-only
//
// cgdemo - the guided live demo AND the automatic test suite of CanaryGuard.
//
//   sudo cgdemo            narrated demo: acts 1-5, press Enter between them
//   sudo cgdemo --auto     no pauses; runs the demo plus extra checks and
//                          prints PASS/FAIL for each (exit code 0 = all passed)
//   options: --no-pause  --keep (leave the demo folders in place)
//
// The demo attacks three throw-away folders in /var/tmp/canaryguard-demo with
// the harmless fake ransomware (ransim) and shows how the driver reacts.
// Everything it does is real: real processes, real files, a real kernel.
#include "cg_common.hpp"
#include "sandbox.hpp"
#include "sha256.hpp"

#include <grp.h>
#include <signal.h>
#include <sys/wait.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

volatile sig_atomic_t g_interrupted = 0;
void onSignal(int) { g_interrupted = 1; }

// ---------------------------------------------------------------------------
// Terminal styling (plain text when output is not a terminal)
// ---------------------------------------------------------------------------

struct Style {
    bool on = ::isatty(STDOUT_FILENO);
    std::string code(const char* c) const { return on ? std::string("\033[") + c + "m" : ""; }
    std::string reset() const { return code("0"); }
    std::string bold() const { return code("1"); }
    std::string dim() const { return code("2"); }
    std::string red() const { return code("1;31"); }
    std::string green() const { return code("1;32"); }
    std::string yellow() const { return code("1;33"); }
    std::string cyan() const { return code("1;36"); }
};

// ---------------------------------------------------------------------------
// Running child programs
// ---------------------------------------------------------------------------

struct Outcome {
    bool signaled = false;
    int signal = 0;
    int code = -1;
    bool killedByGuard() const { return signaled && signal == SIGKILL; }
    bool ok() const { return !signaled && code == 0; }
};

enum class Who { Root, Invoker };   // Invoker = the normal user who ran sudo

using Hashes = std::map<std::string, std::string>;

class Demo {
public:
    Demo(bool autoMode, bool pause, bool keep)
        : auto_(autoMode), pause_(pause && !autoMode && ::isatty(STDIN_FILENO)), keep_(keep), dev_(/*nonblock=*/true) {}

    ~Demo() { cleanup(); }

    int run() {
        prepare();
        intro();
        actNoProtection();
        actCanary();
        actSpeed();
        actHoneytoken();
        actStats();
        if (auto_) extraChecks();
        return finish();
    }

private:
    // ---- output helpers ---------------------------------------------------

    void heading(const std::string& text) {
        std::cout << "\n" << s_.cyan() << "=== " << text << " ===" << s_.reset() << "\n";
    }
    void say(const std::string& text) { std::cout << "  " << text << "\n"; }
    void command(const std::string& text) { std::cout << "  " << s_.dim() << "$ " << text << s_.reset() << "\n"; }

    void check(const std::string& what, bool ok, const std::string& detail = "") {
        ok ? ++passed_ : ++failed_;
        std::cout << "  " << (ok ? s_.green() + "[PASS]" : s_.red() + "[FAIL]") << s_.reset() << " " << what;
        if (!ok && !detail.empty()) std::cout << "   (" << detail << ")";
        std::cout << "\n";
    }

    void checkpoint() {
        if (g_interrupted) throw cg::Error("interrupted");
    }

    void pauseForEnter() {
        checkpoint();
        if (!pause_) return;
        std::cout << "\n  " << s_.dim() << "[press Enter to continue]" << s_.reset() << std::flush;
        std::string ignored;
        std::getline(std::cin, ignored);
        checkpoint();
    }

    // Give the live monitor a moment to print before we narrate the result.
    void settle() { std::this_thread::sleep_for(std::chrono::milliseconds(auto_ ? 20 : 450)); }

    // ---- processes --------------------------------------------------------

    fs::path tool(const std::string& name) const {
        fs::path local = toolDir_ / name;
        return fs::exists(local) ? local : fs::path(name);
    }

    void dropPrivileges() const {
        if (invokerUid_ == 0) return;
        if (::setgroups(0, nullptr) != 0 || ::setgid(invokerGid_) != 0 || ::setuid(invokerUid_) != 0) ::_exit(126);
    }

    Outcome run(std::vector<std::string> args, Who who = Who::Invoker, bool quiet = false) {
        std::cout.flush();
        pid_t pid = ::fork();
        if (pid < 0) throw cg::Error(cg::errnoText("fork", errno));
        if (pid == 0) {
            if (who == Who::Invoker) dropPrivileges();
            if (quiet) {
                int nul = ::open("/dev/null", O_WRONLY);
                ::dup2(nul, 1);
                ::dup2(nul, 2);
            }
            std::string path = tool(args[0]).string();
            std::vector<char*> argv;
            for (std::string& a : args) argv.push_back(a.data());
            argv.push_back(nullptr);
            ::execvp(path.c_str(), argv.data());
            ::_exit(127);
        }
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) checkpoint();
        Outcome o;
        if (WIFSIGNALED(status)) {
            o.signaled = true;
            o.signal = WTERMSIG(status);
            if (!quiet)
                std::cout << "  " << s_.red() << "-> killed by the kernel (signal " << o.signal << ")" << s_.reset() << "\n";
        }
        else if (WIFEXITED(status)) o.code = WEXITSTATUS(status);
        return o;
    }

    // Show a command the way a user would type it, then run it.
    Outcome shown(const std::string& display, std::vector<std::string> args, Who who) {
        command(display);
        return run(std::move(args), who);
    }

    void ctl(const std::vector<std::string>& args) {
        std::string shown_text = "sudo canaryctl";
        std::vector<std::string> argv{"canaryctl"};
        for (const std::string& a : args) { shown_text += " " + a; argv.push_back(a); }
        shown(shown_text, argv, Who::Root);
    }

    // ---- state ------------------------------------------------------------

    cg_stats stats() { return dev_.stats(); }

    std::vector<cg_event> drain() {
        std::vector<cg_event> all;
        for (;;) {
            auto batch = dev_.readEvents();
            if (batch.empty()) break;
            all.insert(all.end(), batch.begin(), batch.end());
        }
        return all;
    }

    static const cg_event* find(const std::vector<cg_event>& evs, const std::function<bool(const cg_event&)>& pred) {
        for (const cg_event& e : evs) if (pred(e)) return &e;
        return nullptr;
    }

    Hashes hashSamples(const fs::path& dir) const {
        Hashes h;
        for (const std::string& name : sandbox::sampleNames()) {
            auto v = cg::Sha256::ofFile((dir / name).string());
            if (v) h[name] = *v;
        }
        return h;
    }

    Hashes hashBait(const fs::path& dir) const {
        Hashes h;
        for (const char* name : {"Budget_2026.xlsx", "Family_Photos_Backup.zip", "Tax_Returns_2025.pdf", "passwords.txt",
                                 "server_login_backup.txt"}) {
            auto v = cg::Sha256::ofFile((dir / name).string());
            if (v) h[name] = *v;
        }
        return h;
    }

    // Undo an attack. In "kill" mode a restore of many files would itself look
    // like an attack, so the restore runs in warn mode.
    void restore(const fs::path& dir) {
        cg_config c = dev_.config();
        uint32_t oldMode = c.mode;
        c.mode = CG_MODE_WARN;
        dev_.setConfig(c);
        command("ransim --restore " + dir.string());
        run({"ransim", "--restore", dir.string()}, Who::Invoker);
        c.mode = oldMode;
        dev_.setConfig(c);
        drain();                       // the restore's own alerts are not interesting
    }

    // ---- set-up and tear-down --------------------------------------------

    void prepare() {
        char self[4096];
        ssize_t n = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
        toolDir_ = n > 0 ? fs::path(std::string(self, static_cast<size_t>(n))).parent_path() : fs::path(".");

        if (const char* u = std::getenv("SUDO_UID")) invokerUid_ = static_cast<uid_t>(std::strtoul(u, nullptr, 10));
        if (const char* g = std::getenv("SUDO_GID")) invokerGid_ = static_cast<gid_t>(std::strtoul(g, nullptr, 10));

        struct sigaction sa{};
        sa.sa_handler = onSignal;                // no SA_RESTART: Enter-prompts can be interrupted
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);

        if (dev_.stats().open_handles > 1 && auto_)
            throw cg::Error("another program (canaryd?) has the driver open and would steal the events: stop it first");

        // start from a known state
        dev_.clear();
        cg_config c{CG_MODE_KILL, 1, CG_DEFAULT_SPEED_THRESHOLD, CG_DEFAULT_SPEED_WINDOW_MS};
        dev_.setConfig(c);
        try { dev_.disallow("ransim"); } catch (const cg::Error&) {}
        dev_.resetStats();
        drain();

        removeOldSandboxes();
        fs::create_directories(root_);
        giveToInvoker(root_);
        for (const fs::path& dir : {none_, bait_, speed_}) {
            sandbox::setup(dir, invokerUid_, invokerGid_);
            originals_[dir.string()] = hashSamples(dir);
        }

        if (!auto_ && dev_.stats().open_handles <= 1) startMonitor();
    }

    void giveToInvoker(const fs::path& p) const {
        if (::chown(p.c_str(), invokerUid_, invokerGid_) != 0) { /* best effort */ }
    }

    void removeOldSandboxes() {
        std::error_code ec;
        if (!fs::exists(root_, ec)) return;
        for (const auto& entry : fs::directory_iterator(root_)) {
            if (!entry.is_directory() || !sandbox::isSandbox(entry.path()))
                throw cg::Error(root_.string() + " contains something that is not a demo folder: please remove it by hand");
            fs::remove_all(entry.path(), ec);
        }
        fs::remove(root_, ec);
    }

    void startMonitor() {
        std::cout.flush();
        monitor_ = ::fork();
        if (monitor_ == 0) {
            std::string path = tool("canaryd").string();
            ::execl(path.c_str(), "canaryd", "--interval", "3", static_cast<char*>(nullptr));
            ::_exit(127);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
    }

    void stopMonitor() {
        if (monitor_ > 0) {
            ::kill(monitor_, SIGTERM);
            ::waitpid(monitor_, nullptr, 0);
            monitor_ = -1;
        }
    }

    void cleanup() {
        if (cleaned_) return;
        cleaned_ = true;
        stopMonitor();
        try {
            dev_.clear();
            cg_config c{CG_MODE_KILL, 1, CG_DEFAULT_SPEED_THRESHOLD, CG_DEFAULT_SPEED_WINDOW_MS};
            dev_.setConfig(c);
            try { dev_.disallow("ransim"); } catch (const cg::Error&) {}
        } catch (const std::exception&) {}
        if (!keep_) {
            std::error_code ec;
            for (const fs::path& dir : {none_, bait_, speed_}) if (sandbox::isSandbox(dir)) fs::remove_all(dir, ec);
            fs::remove(root_, ec);
        }
    }

    // ---- the story --------------------------------------------------------

    void intro() {
        heading("CanaryGuard: stopping ransomware inside the Linux kernel");
        say("Ransomware scrambles every file it can reach and then demands money.");
        say("CanaryGuard is a driver INSIDE the kernel. Every program must ask the kernel");
        say("before it opens, changes or deletes a file, so the driver sees every attempt.");
        say("");
        say("Three layers of defence:");
        say("  1. canary files    bait documents that no real user ever changes");
        say("  2. speed check     no human changes 10 different files in 2 seconds");
        say("  3. honeytoken      a fake password file; anyone who reads it is snooping");
        say("");
        say("The attacker today is 'ransim': a HARMLESS imitation of ransomware that only");
        say("works inside the demo folders in " + root_.string() + ".");
        if (monitor_ > 0) say("The live alert monitor (canaryd) is running below and prints every alert.");
        pauseForEnter();
    }

    void actNoProtection() {
        heading("Act 1: an attack WITHOUT protection");
        say("Folder 1_unprotected is not guarded. Let's see what ransomware does to it.");
        auto before = stats();
        shown("ransim --attack " + none_.string(), {"ransim", "--attack", none_.string()}, Who::Invoker);
        settle();
        size_t locked = sandbox::countLocked(none_);
        check("nothing stopped the attack: " + std::to_string(locked) + " of 20 files are encrypted", locked == 20);
        check("the driver recorded no events (nothing was registered)", stats().events == before.events);
        say("Every document is now '.locked' and unreadable. This is the problem we solve.");
        restore(none_);
        check("restore brought every file back, byte for byte", restoredOk(none_));
        pauseForEnter();
    }

    void actCanary() {
        heading("Act 2: layer 1, canary files");
        say("We plant bait files (Budget_2026.xlsx and others) in 2_bait with canaryctl.");
        say("To a thief they look valuable. To us they are tripwires: nobody legitimate touches them.");
        ctl({"plant", bait_.string()});
        bait_hashes_ = hashBait(bait_);
        drain();
        auto before = stats();
        say("");
        say("Now the same attack, on the guarded folder:");
        Outcome o = shown("ransim --attack " + bait_.string(), {"ransim", "--attack", bait_.string()}, Who::Invoker);
        settle();
        auto after = stats();
        size_t locked = sandbox::countLocked(bait_);
        check("ransim was KILLED by the kernel (SIGKILL)", o.killedByGuard());
        check("it got through only " + std::to_string(locked) + " files before it touched a canary", locked == 3);
        check("the canary files are untouched", hashBait(bait_) == bait_hashes_);
        check("driver counters: 1 canary hit, 1 process killed",
              after.canary_hits == before.canary_hits + 1 && after.kills == before.kills + 1);
        if (auto_) {
            auto evs = drain();
            const cg_event* e = find(evs, [](const cg_event& x) { return x.type == CG_EV_CANARY; });
            check("alert says: ransim tried to WRITE Budget_2026.xlsx and was KILLED",
                  e && std::string(e->comm) == "ransim" && std::string(e->file) == "Budget_2026.xlsx" &&
                      e->op == CG_OP_WRITE && e->action == CG_ACTION_KILLED);
        }
        say("The kernel refused the write AND killed the attacker. The few files it already");
        say("scrambled are the price: the guard limits the damage, it cannot undo it.");
        restore(bait_);
        check("restore brought the 3 encrypted files back", restoredOk(bait_));
        pauseForEnter();
    }

    void actSpeed() {
        heading("Act 3: layer 2, the speed check");
        say("What if the ransomware avoids the bait? Folder 3_speed has NO bait files at all,");
        say("we only tell the driver to watch it. The rule: 10 different files within 2 seconds.");
        ctl({"watch", speed_.string()});
        drain();
        auto before = stats();
        cg_config cfg = dev_.config();
        Outcome o = shown("ransim --attack " + speed_.string(), {"ransim", "--attack", speed_.string()}, Who::Invoker);
        settle();
        auto after = stats();
        size_t locked = sandbox::countLocked(speed_);
        check("ransim was KILLED by the kernel (SIGKILL)", o.killedByGuard());
        check("only " + std::to_string(locked) + " files were encrypted: the 10th file was protected",
              locked == cfg.speed_threshold - 1);
        check("driver counters: 1 speed-check hit, 1 process killed",
              after.speed_hits == before.speed_hits + 1 && after.kills == before.kills + 1);
        if (auto_) {
            auto evs = drain();
            const cg_event* e = find(evs, [](const cg_event& x) { return x.type == CG_EV_SPEED; });
            check("alert says: ransim changed 10 files within 2000 ms",
                  e && std::string(e->comm) == "ransim" && e->count == cfg.speed_threshold &&
                      e->window_ms == cfg.speed_window_ms && e->action == CG_ACTION_KILLED);
        }
        say("Behaviour, not names: it caught an attacker that never touched a bait file.");
        restore(speed_);
        check("restore brought the files back", restoredOk(speed_));
        pauseForEnter();
    }

    void actHoneytoken() {
        heading("Act 4: the honeytoken (fake secrets)");
        say("planted in 2_bait is a file called passwords.txt. Its content is fake; nobody honest");
        say("needs it. A thief searching for saved passwords will open it:");
        drain();
        auto before = stats();
        Outcome o = shown("cat " + (bait_ / "passwords.txt").string(), {"cat", (bait_ / "passwords.txt").string()}, Who::Invoker);
        settle();
        auto after = stats();
        check("cat was NOT killed (reading is only suspicious, not destructive)", o.ok());
        check("but the driver raised a honeytoken alert", after.honeytoken_hits == before.honeytoken_hits + 1);
        if (auto_) {
            auto evs = drain();
            const cg_event* e = find(evs, [](const cg_event& x) { return x.type == CG_EV_HONEYTOKEN; });
            check("alert says: cat (a known process, a known user) read passwords.txt",
                  e && std::string(e->comm) == "cat" && e->op == CG_OP_READ && e->action == CG_ACTION_ALERT);
        }
        say("We know WHICH program and WHICH user looked at the secrets, at the exact second.");
        pauseForEnter();
    }

    void actStats() {
        heading("Act 5: what the driver knows");
        ctl({"list"});
        ctl({"stats"});
        command("cat /sys/class/canaryguard/canaryguard/stats      (the same numbers through sysfs)");
        std::cout.flush();
        run({"cat", "/sys/class/canaryguard/canaryguard/stats"}, Who::Invoker);
        pauseForEnter();
    }

    // ---- extra checks (--auto only) ------------------------------------------

    void extraChecks() {
        heading("Extra checks");
        drain();
        cg_config cfg = dev_.config();

        // warn mode: alert, never kill
        {
            say("warn mode: the attack is only reported, never stopped");
            cfg.mode = CG_MODE_WARN;
            dev_.setConfig(cfg);
            auto before = stats();
            Outcome o = run({"ransim", "--attack", speed_.string()}, Who::Invoker, true);
            auto after = stats();
            check("ransim ran to the end", o.ok() && sandbox::countLocked(speed_) == 20);
            check("the driver only alerted (2 speed alerts, 0 kills)",
                  after.speed_hits == before.speed_hits + 2 && after.kills == before.kills);
            drain();
            cfg.mode = CG_MODE_KILL;
            dev_.setConfig(cfg);
            restore(speed_);
            check("files restored", restoredOk(speed_));
        }

        // safe list
        {
            say("safe list: a trusted process name is never touched");
            dev_.allow("ransim");
            auto before = stats();
            Outcome o = run({"ransim", "--attack", speed_.string()}, Who::Invoker, true);
            check("an allow-listed 'ransim' finished its run", o.ok() && sandbox::countLocked(speed_) == 20);
            check("no alert, no kill", stats().events == before.events && stats().kills == before.kills);
            run({"ransim", "--restore", speed_.string()}, Who::Invoker, true);
            dev_.disallow("ransim");
            check("files restored", restoredOk(speed_));
        }

        // normal work must not be disturbed
        {
            say("normal work: ordinary programs are left alone");
            fs::path copies = speed_ / "copies";
            fs::create_directories(copies);
            giveToInvoker(copies);
            std::vector<std::string> cp{"cp", "--target-directory=" + copies.string()};
            for (int i = 0; i < 5; ++i) cp.push_back((speed_ / sandbox::sampleNames()[i]).string());
            auto before = stats();
            Outcome o = run(cp, Who::Invoker, true);
            check("copying 5 files inside a watched folder is not disturbed", o.ok() && stats().events == before.events);

            std::vector<std::string> cp12{"cp", "--target-directory=" + copies.string()};
            for (int i = 5; i < 17; ++i) cp12.push_back((speed_ / sandbox::sampleNames()[i]).string());
            o = run(cp12, Who::Invoker, true);
            check("copying 12 files at once IS stopped (documented trade-off: use 'canaryctl allow cp')",
                  o.killedByGuard());
            drain();
            std::error_code ec;
            fs::remove_all(copies, ec);
        }

        // delete / rename of a canary
        {
            say("deleting or renaming a canary");
            fs::path canary = bait_ / "Tax_Returns_2025.pdf";
            Outcome rm = run({"rm", "-f", canary.string()}, Who::Invoker, true);
            check("rm was killed and the canary still exists", rm.killedByGuard() && fs::exists(canary));
            Outcome mv = run({"mv", canary.string(), (bait_ / "tax.old").string()}, Who::Invoker, true);
            check("mv was killed and the canary kept its name", mv.killedByGuard() && fs::exists(canary) && !fs::exists(bait_ / "tax.old"));
            auto evs = drain();
            check("alerts name the operations 'delete' and 'rename'",
                  find(evs, [](const cg_event& x) { return x.op == CG_OP_UNLINK; }) &&
                      find(evs, [](const cg_event& x) { return x.op == CG_OP_RENAME; }));
        }

        // layering
        {
            say("layers: a SLOW attacker passes the speed check, but not the canary");
            Outcome slowSpeed = run({"ransim", "--attack", speed_.string(), "--delay-ms", "250"}, Who::Invoker, true);
            check("slow attack on the folder with only the speed check: not stopped (known limitation)",
                  slowSpeed.ok() && sandbox::countLocked(speed_) == 20);
            restore(speed_);
            Outcome slowBait = run({"ransim", "--attack", bait_.string(), "--delay-ms", "250"}, Who::Invoker, true);
            check("the same slow attack on the bait folder: killed at the canary",
                  slowBait.killedByGuard() && sandbox::countLocked(bait_) == 3);
            drain();
            restore(bait_);
            check("files restored", restoredOk(bait_) && restoredOk(speed_));
        }

        // ring buffer
        {
            say("ring buffer: events are never lost silently");
            drain();
            auto before = stats();
            run({"ransim", "--snoop", (bait_ / "passwords.txt").string(), "--times", "200"}, Who::Invoker, true);
            auto after = stats();
            auto evs = drain();
            check("200 events raised: 128 kept, 72 counted as dropped",
                  after.events - before.events == 200 && after.dropped - before.dropped == 72 && evs.size() == CG_RING_EVENTS);
        }

        // input validation and security
        {
            say("the driver says no to bad requests");
            auto fails = [&](const std::function<void()>& fn, int wantErrno) {
                try { fn(); } catch (const cg::Error& e) { return std::string(e.what()).find(std::strerror(wantErrno)) != std::string::npos; }
                return false;
            };
            check("refuses to watch /usr", fails([&] { dev_.add(CG_KIND_WATCHDIR, "/usr"); }, EPERM));
            check("refuses to watch /", fails([&] { dev_.add(CG_KIND_WATCHDIR, "/"); }, EPERM));
            check("refuses a path that does not exist", fails([&] { dev_.add(CG_KIND_CANARY, "/var/tmp/no-such-file"); }, ENOENT));
            check("refuses a file as a watched folder", fails([&] { dev_.add(CG_KIND_WATCHDIR, (bait_ / "passwords.txt").string()); }, ENOTDIR));
            check("refuses to register the same file twice", fails([&] { dev_.add(CG_KIND_CANARY, (bait_ / "Budget_2026.xlsx").string()); }, EEXIST));
            cg_config bad = dev_.config();
            bad.speed_threshold = 1;
            check("refuses a speed limit of 1 file", fails([&] { dev_.setConfig(bad); }, EINVAL));
            bad = dev_.config();
            bad.speed_window_ms = 50;
            check("refuses a 50 ms window", fails([&] { dev_.setConfig(bad); }, EINVAL));

            if (invokerUid_ != 0) {
                pid_t pid = ::fork();
                if (pid == 0) {
                    dropPrivileges();
                    int fd = ::open(CG_DEVICE_PATH, O_RDWR);
                    ::_exit(fd < 0 && errno == EACCES ? 0 : 1);
                }
                int st = 0;
                ::waitpid(pid, &st, 0);
                check("a normal user cannot open /dev/canaryguard", WIFEXITED(st) && WEXITSTATUS(st) == 0);
            }
            check("the built-in SHA-256 matches the official test vector",
                  cg::Sha256::ofString("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }

        // the live monitor (must be last: it reads the events itself)
        {
            say("the live monitor (canaryd): alerts reach a log file, tampering is noticed");
            const fs::path log = "/tmp/canaryguard-cgdemo-monitor.log";
            std::error_code ec;
            fs::remove(log, ec);
            drain();
            pid_t mon = ::fork();
            if (mon == 0) {
                int nul = ::open("/dev/null", O_WRONLY);
                ::dup2(nul, 1);
                ::dup2(nul, 2);
                std::string path = tool("canaryd").string();
                ::execl(path.c_str(), "canaryd", "--no-color", "--interval", "1", "--log", log.c_str(),
                        static_cast<char*>(nullptr));
                ::_exit(127);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(700));

            run({"ransim", "--attack", bait_.string()}, Who::Invoker, true);
            check("canaryd logged the KILLED alert for ransim",
                  waitForLog(log, "KILLED", std::chrono::seconds(3)) && waitForLog(log, "ransim", std::chrono::seconds(1)));
            run({"ransim", "--restore", bait_.string()}, Who::Invoker, true);

            // change a canary behind the driver's back (the safe list lets 'truncate' through)
            dev_.allow("truncate");
            run({"truncate", "-s", "0", (bait_ / "Tax_Returns_2025.pdf").string()}, Who::Invoker, true);
            dev_.disallow("truncate");
            check("canaryd noticed that a canary file was changed behind the driver's back",
                  waitForLog(log, "INTEGRITY", std::chrono::seconds(5)));

            ::kill(mon, SIGTERM);
            int st = 0;
            ::waitpid(mon, &st, 0);
            check("canaryd stopped cleanly on SIGTERM", WIFEXITED(st) && WEXITSTATUS(st) == 0 && waitForLog(log, "STOP", std::chrono::seconds(1)));
            fs::remove(log, ec);
        }
    }

    static bool waitForLog(const fs::path& log, const std::string& needle, std::chrono::milliseconds limit) {
        auto deadline = std::chrono::steady_clock::now() + limit;
        while (std::chrono::steady_clock::now() < deadline) {
            std::ifstream in(log);
            std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            if (text.find(needle) != std::string::npos) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    }

    bool restoredOk(const fs::path& dir) const {
        return sandbox::countLocked(dir) == 0 && hashSamples(dir) == originals_.at(dir.string());
    }

    int finish() {
        stopMonitor();
        heading(auto_ ? "Result" : "The end");
        if (auto_) {
            std::cout << "  " << passed_ << " passed, " << failed_ << " failed\n";
            if (failed_ == 0) std::cout << "  " << s_.green() << "ALL CHECKS PASSED" << s_.reset() << "\n";
            else std::cout << "  " << s_.red() << "SOME CHECKS FAILED" << s_.reset() << "\n";
            return failed_ == 0 ? 0 : 1;
        }
        say("Layer 1 stopped the attacker at the first bait file (3 files lost).");
        say("Layer 2 stopped it with no bait at all (9 files lost).");
        say("Layer 3 told us who was snooping around the fake passwords.");
        say("And every alert reached user space through a ring buffer, via /dev/canaryguard.");
        std::cout << "\n  " << passed_ << " checks passed, " << failed_ << " failed\n";
        return failed_ == 0 ? 0 : 1;
    }

    Style s_;
    bool auto_, pause_, keep_;
    cg::Device dev_;
    uid_t invokerUid_ = 0;
    gid_t invokerGid_ = 0;
    fs::path toolDir_;
    fs::path root_{sandbox::kRoot};
    fs::path none_ = root_ / "1_unprotected";
    fs::path bait_ = root_ / "2_bait";
    fs::path speed_ = root_ / "3_speed";
    std::map<std::string, Hashes> originals_;
    Hashes bait_hashes_;
    pid_t monitor_ = -1;
    int passed_ = 0, failed_ = 0;
    bool cleaned_ = false;
};

void usage() {
    std::cout << "cgdemo - guided demo and automatic tests for CanaryGuard\n\n"
                 "  sudo cgdemo            narrated demo (press Enter between acts)\n"
                 "  sudo cgdemo --auto     run everything without pauses, print PASS/FAIL\n"
                 "  options: --no-pause  --keep\n";
}

}  // namespace

int main(int argc, char** argv) {
    bool autoMode = false, pause = true, keep = false;
    for (int i = 1; i < argc; ++i) {
        std::string opt = argv[i];
        if (opt == "--auto") autoMode = true;
        else if (opt == "--no-pause") pause = false;
        else if (opt == "--keep") keep = true;
        else if (opt == "-h" || opt == "--help") { usage(); return 0; }
        else { std::cerr << "cgdemo: unknown option " << opt << "\n"; usage(); return 1; }
    }
    if (::geteuid() != 0) {
        std::cerr << "cgdemo: run with sudo (it talks to the kernel driver)\n";
        return 1;
    }
    try {
        Demo demo(autoMode, pause, keep);
        return demo.run();
    } catch (const std::exception& e) {
        std::cerr << "\ncgdemo: " << e.what() << "\n";
        return 1;
    }
}
