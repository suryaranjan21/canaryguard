// SPDX-License-Identifier: GPL-2.0-only
//
// canaryd - the live alert monitor for the CanaryGuard driver.
//
//   canaryd                       show alerts on screen until Ctrl+C
//   canaryd --log FILE            also append every alert to FILE
//   canaryd --daemon [--log FILE] run in the background (default log:
//                                 /var/log/canaryguard.log, pid in /run/canaryd.pid;
//                                 stop it with: sudo kill $(cat /run/canaryd.pid))
//   canaryd --interval SECONDS    how often canary files are re-checked (default 5)
//   canaryd --no-integrity        skip the periodic canary check
//   canaryd --selftest            check the built-in SHA-256 and exit
//
// Two jobs:
//   1. read security events from the kernel (/dev/canaryguard) and display them
//   2. every few seconds, re-hash every canary file and warn if one changed or
//      vanished behind the driver's back (a second line of defence)
#include "cg_common.hpp"
#include "sha256.hpp"

#include <signal.h>
#include <sys/signalfd.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr const char* kPidFile = "/run/canaryd.pid";

// ---------------------------------------------------------------------------
// Alert delivery. The bus knows nothing about screens or files: it hands each
// alert to every registered sink (the Observer pattern), so adding a new
// destination (e-mail, network ...) does not change the rest of the program.
// ---------------------------------------------------------------------------

class AlertSink {
public:
    virtual ~AlertSink() = default;
    virtual void deliver(const cg::Alert& alert) = 0;
};

class ConsoleSink : public AlertSink {
public:
    explicit ConsoleSink(bool colour) : colour_(colour) {}

    void deliver(const cg::Alert& a) override {
        const char* on = "";
        const char* off = "";
        if (colour_) {
            off = "\033[0m";
            switch (a.severity) {
                case cg::Severity::Critical: on = "\033[1;97;41m"; break;   // white on red
                case cg::Severity::Warning: on = "\033[1;30;43m"; break;    // black on yellow
                default: on = "\033[1;36m"; break;                          // cyan
            }
        }
        std::string tag = " " + a.tag + std::string(a.tag.size() < 9 ? 9 - a.tag.size() : 0, ' ') + " ";
        std::cout << cg::timeText(a.when_ns) << "  " << on << tag << off << "  " << a.message << std::endl;
    }

private:
    bool colour_;
};

class FileSink : public AlertSink {
public:
    explicit FileSink(const std::string& path) : out_(path, std::ios::app) {
        if (!out_) throw cg::Error("cannot open log file " + path);
    }
    void deliver(const cg::Alert& a) override {
        out_ << cg::timeText(a.when_ns, true) << " " << a.tag << " " << a.message << std::endl;
    }

private:
    std::ofstream out_;
};

class AlertBus {
public:
    void add(std::unique_ptr<AlertSink> sink) { sinks_.push_back(std::move(sink)); }

    // Called from two threads (events + integrity check): the mutex keeps
    // the output lines from mixing.
    void publish(const cg::Alert& alert) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& sink : sinks_) sink->deliver(alert);
    }

    void info(const std::string& tag, const std::string& message) {
        cg::Alert a;
        a.severity = cg::Severity::Info;
        a.when_ns = static_cast<uint64_t>(std::time(nullptr)) * 1000000000ull;
        a.tag = tag;
        a.message = message;
        publish(a);
    }

private:
    std::vector<std::unique_ptr<AlertSink>> sinks_;
    std::mutex mutex_;
};

// ---------------------------------------------------------------------------
// Integrity watcher: a background thread that re-hashes the canary files.
// ---------------------------------------------------------------------------

class IntegrityWatcher {
public:
    IntegrityWatcher(cg::Device& dev, AlertBus& bus, std::chrono::seconds interval)
        : dev_(dev), bus_(bus), interval_(interval) {}
    ~IntegrityWatcher() { stop(); }

    void start() { thread_ = std::thread([this] { run(); }); }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        wake_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!stopping_) {
            lock.unlock();
            try {
                scan();
            } catch (const std::exception& e) {
                bus_.info("WARN", std::string("integrity check failed: ") + e.what());
            }
            lock.lock();
            wake_.wait_for(lock, interval_, [this] { return stopping_; });
        }
    }

    void scan() {
        std::map<std::string, std::optional<std::string>> now;
        for (const cg_entry& e : dev_.entries())
            if (e.kind == CG_KIND_CANARY) now[e.path] = cg::Sha256::ofFile(e.path);

        for (const auto& [path, hash] : now) {
            auto known = baseline_.find(path);
            if (known == baseline_.end()) {          // first time we see it: remember it
                baseline_[path] = hash;
                continue;
            }
            if (known->second == hash) continue;      // unchanged

            cg::Alert a;
            a.severity = cg::Severity::Critical;
            a.when_ns = static_cast<uint64_t>(std::time(nullptr)) * 1000000000ull;
            a.tag = "INTEGRITY";
            a.message = hash ? "canary file CHANGED behind the driver's back: " + path
                             : "canary file is MISSING: " + path;
            bus_.publish(a);
            known->second = hash;                     // report each change once
        }
        for (auto it = baseline_.begin(); it != baseline_.end();)   // forget unregistered files
            it = now.count(it->first) ? std::next(it) : baseline_.erase(it);
    }

    cg::Device& dev_;
    AlertBus& bus_;
    std::chrono::seconds interval_;
    std::map<std::string, std::optional<std::string>> baseline_;
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_ = false;
};

// ---------------------------------------------------------------------------
// Running in the background: the classic double-fork daemon recipe.
// ---------------------------------------------------------------------------

void daemonize(const std::string& pidfile) {
    pid_t pid = ::fork();
    if (pid < 0) throw cg::Error(cg::errnoText("fork", errno));
    if (pid > 0) ::_exit(0);          // the original process ends
    ::setsid();                       // new session: no controlling terminal
    pid = ::fork();
    if (pid < 0) throw cg::Error(cg::errnoText("fork", errno));
    if (pid > 0) ::_exit(0);          // the session leader ends: we can never get a terminal back
    ::umask(027);
    if (::chdir("/") != 0) { /* harmless */ }
    int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        ::dup2(devnull, 0);
        ::dup2(devnull, 1);
        ::dup2(devnull, 2);
        if (devnull > 2) ::close(devnull);
    }
    std::ofstream(pidfile) << ::getpid() << "\n";
}

int selfTest() {
    const std::string got = cg::Sha256::ofString("abc");
    const std::string want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    std::cout << "SHA-256(\"abc\") " << (got == want ? "OK" : "WRONG: " + got) << "\n";
    return got == want ? 0 : 1;
}

void usage() {
    std::cout << "canaryd - live alert monitor for CanaryGuard\n\n"
                 "  canaryd [--log FILE] [--daemon] [--interval SECONDS] [--no-integrity] [--no-color]\n"
                 "  canaryd --selftest\n\n"
                 "Needs root: run with sudo. The driver must be loaded ('sudo make load').\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::string logPath;
    bool daemon = false, integrity = true, colour = ::isatty(STDOUT_FILENO);
    int intervalSec = 5;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string opt = argv[i];
            auto value = [&]() -> std::string {
                if (i + 1 >= argc) throw cg::Error("missing value after " + opt);
                return argv[++i];
            };
            if (opt == "--log") logPath = value();
            else if (opt == "--daemon") daemon = true;
            else if (opt == "--interval") intervalSec = std::max(1, std::stoi(value()));
            else if (opt == "--no-integrity") integrity = false;
            else if (opt == "--no-color") colour = false;
            else if (opt == "--selftest") return selfTest();
            else if (opt == "-h" || opt == "--help") { usage(); return 0; }
            else throw cg::Error("unknown option: " + opt);
        }

        if (daemon && logPath.empty()) logPath = "/var/log/canaryguard.log";

        // Fail early (and visibly) if the driver is not there, before we detach.
        { cg::Device probe; }

        // Block SIGINT/SIGTERM and receive them as ordinary data on a file
        // descriptor: they then fit into the same poll() loop as the events.
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigprocmask(SIG_BLOCK, &mask, nullptr);

        if (daemon) daemonize(kPidFile);   // must happen before any thread exists

        cg::Fd sigFd(::signalfd(-1, &mask, SFD_CLOEXEC));
        if (!sigFd) throw cg::Error(cg::errnoText("signalfd", errno));

        cg::Device dev(/*nonblock=*/true);

        AlertBus bus;
        if (!daemon) bus.add(std::make_unique<ConsoleSink>(colour));
        if (!logPath.empty()) bus.add(std::make_unique<FileSink>(logPath));

        std::unique_ptr<IntegrityWatcher> watcher;
        if (integrity) {
            watcher = std::make_unique<IntegrityWatcher>(dev, bus, std::chrono::seconds(intervalSec));
            watcher->start();
        }

        cg_config cfg = dev.config();
        bus.info("READY", std::string("monitoring /dev/canaryguard, mode=") +
                              (cfg.mode == CG_MODE_KILL ? "kill" : "warn") + (daemon ? " (daemon)" : "  (Ctrl+C to stop)"));

        uint64_t lastDropped = dev.stats().dropped;
        pollfd fds[2] = {{dev.fd(), POLLIN, 0}, {sigFd.get(), POLLIN, 0}};

        for (bool running = true; running;) {
            if (::poll(fds, 2, -1) < 0) {
                if (errno == EINTR) continue;
                throw cg::Error(cg::errnoText("poll", errno));
            }
            if (fds[1].revents & POLLIN) {          // Ctrl+C or kill
                signalfd_siginfo si;
                if (::read(sigFd.get(), &si, sizeof(si)) < 0) { /* ignore */ }
                running = false;
            }
            if (fds[0].revents & POLLIN) {
                for (const cg_event& ev : dev.readEvents()) bus.publish(cg::alertFromEvent(ev));

                // The kernel ring buffer is finite: say so if events were lost.
                uint64_t dropped = dev.stats().dropped;
                if (dropped > lastDropped) {
                    bus.info("WARN", std::to_string(dropped - lastDropped) +
                                         " event(s) were lost because the ring buffer was full");
                    lastDropped = dropped;
                }
            }
        }

        if (watcher) watcher->stop();
        bus.info("STOP", "monitor stopped");
        if (daemon) ::unlink(kPidFile);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "canaryd: " << e.what() << "\n";
        return 1;
    }
}
