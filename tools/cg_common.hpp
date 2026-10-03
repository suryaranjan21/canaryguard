// SPDX-License-Identifier: GPL-2.0-only
//
// cg_common.hpp - helpers shared by canaryctl, canaryd and cgdemo.
//
//   cg::Fd      owns a file descriptor and closes it automatically (RAII)
//   cg::Device  a typed wrapper around /dev/canaryguard
//   cg::Alert   a human-readable message built from a kernel event
#pragma once

#include <canaryguard_uapi.h>

#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// The kernel module checks the same sizes when it is built.
static_assert(sizeof(cg_event) == 384, "cg_event layout changed");
static_assert(sizeof(cg_entry) == 272, "cg_entry layout changed");
static_assert(sizeof(cg_add_req) == 264, "cg_add_req layout changed");
static_assert(sizeof(cg_get_entry) == 280, "cg_get_entry layout changed");
static_assert(sizeof(cg_stats) == 64, "cg_stats layout changed");
static_assert(sizeof(cg_config) == 16, "cg_config layout changed");
static_assert(sizeof(cg_allow) == 24, "cg_allow layout changed");

namespace cg {

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

inline std::string errnoText(const std::string& what, int err) {
    return what + ": " + std::strerror(err);
}

// ---------------------------------------------------------------------------
// Fd: RAII wrapper. The descriptor is closed when the object goes away, so we
// cannot leak it, even when an exception is thrown.
// ---------------------------------------------------------------------------

class Fd {
public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : fd_(other.release()) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    ~Fd() { reset(); }

    int get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }

    int release() {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }
    void reset(int fd = -1) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

// ---------------------------------------------------------------------------
// Device: talks to the kernel driver.
// ---------------------------------------------------------------------------

class Device {
public:
    explicit Device(bool nonblock = false, const char* path = CG_DEVICE_PATH) {
        int flags = O_RDWR | O_CLOEXEC | (nonblock ? O_NONBLOCK : 0);
        fd_.reset(::open(path, flags));
        if (!fd_) {
            int err = errno;
            std::string msg = errnoText(std::string("cannot open ") + path, err);
            if (err == ENOENT)
                msg += " (the driver is not loaded: run 'sudo make load')";
            else if (err == EACCES || err == EPERM)
                msg += " (run this program with sudo)";
            throw Error(msg);
        }
    }

    int fd() const { return fd_.get(); }

    // Register a file or folder. Returns the id the driver gave it.
    uint32_t add(uint32_t kind, const std::string& path) {
        if (path.size() >= CG_PATH_MAX) throw Error("path too long: " + path);
        cg_add_req req{};
        req.kind = kind;
        std::strncpy(req.path, path.c_str(), sizeof(req.path) - 1);
        call(CG_IOC_ADD, &req, "register " + path);
        return req.id;
    }

    void remove(uint32_t id) { call(CG_IOC_REMOVE, &id, "remove entry"); }
    void clear() { callNoArg(CG_IOC_CLEAR, "clear all entries"); }

    std::vector<cg_entry> entries() {
        std::vector<cg_entry> out;
        for (uint32_t i = 0;; ++i) {
            cg_get_entry ge{};
            ge.index = i;
            if (::ioctl(fd_.get(), CG_IOC_GET_ENTRY, &ge) < 0) {
                if (errno == ENOENT) break;     // end of the list
                throw Error(errnoText("list entries", errno));
            }
            out.push_back(ge.entry);
        }
        return out;
    }

    cg_stats stats() {
        cg_stats s{};
        call(CG_IOC_GET_STATS, &s, "read statistics");
        return s;
    }

    cg_config config() {
        cg_config c{};
        call(CG_IOC_GET_CONFIG, &c, "read settings");
        return c;
    }
    void setConfig(const cg_config& c) {
        cg_config copy = c;
        call(CG_IOC_SET_CONFIG, &copy, "change settings");
    }

    void allow(const std::string& comm) { allowCall(CG_IOC_ALLOW_ADD, comm, "add to safe list"); }
    void disallow(const std::string& comm) { allowCall(CG_IOC_ALLOW_DEL, comm, "remove from safe list"); }
    std::vector<std::string> allowList() {
        std::vector<std::string> out;
        for (uint32_t i = 0;; ++i) {
            cg_allow al{};
            al.index = i;
            if (::ioctl(fd_.get(), CG_IOC_ALLOW_GET, &al) < 0) {
                if (errno == ENOENT) break;
                throw Error(errnoText("read safe list", errno));
            }
            out.emplace_back(al.comm);
        }
        return out;
    }

    // Read whatever events are waiting. Returns an empty vector when there
    // are none (non-blocking device) or the call was interrupted.
    std::vector<cg_event> readEvents(size_t max = 32) {
        std::vector<cg_event> buf(max);
        ssize_t n = ::read(fd_.get(), buf.data(), buf.size() * sizeof(cg_event));
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) return {};
            throw Error(errnoText("read events", errno));
        }
        buf.resize(static_cast<size_t>(n) / sizeof(cg_event));
        return buf;
    }

private:
    template <typename T>
    void call(unsigned long request, T* arg, const std::string& what) {
        if (::ioctl(fd_.get(), request, arg) < 0) throw Error(errnoText("cannot " + what, errno));
    }
    void callNoArg(unsigned long request, const std::string& what) {
        if (::ioctl(fd_.get(), request) < 0) throw Error(errnoText("cannot " + what, errno));
    }
    void allowCall(unsigned long request, const std::string& comm, const std::string& what) {
        if (comm.empty() || comm.size() >= CG_COMM_LEN)
            throw Error("process names must be 1-" + std::to_string(CG_COMM_LEN - 1) + " characters: " + comm);
        cg_allow al{};
        std::strncpy(al.comm, comm.c_str(), sizeof(al.comm) - 1);
        call(request, &al, what);
    }

    Fd fd_;
};

// ---------------------------------------------------------------------------
// Turning kernel events into readable text
// ---------------------------------------------------------------------------

inline std::string timeText(uint64_t ns, bool withDate = false) {
    std::time_t t = static_cast<std::time_t>(ns / 1000000000ull);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), withDate ? "%Y-%m-%d %H:%M:%S" : "%H:%M:%S", &tm);
    return buf;
}

inline std::string userText(uint32_t uid) {
    passwd pwd{};
    passwd* res = nullptr;
    char buf[1024];
    if (getpwuid_r(uid, &pwd, buf, sizeof(buf), &res) == 0 && res)
        return std::to_string(uid) + "(" + res->pw_name + ")";
    return std::to_string(uid);
}

inline const char* kindName(uint32_t kind) {
    switch (kind) {
        case CG_KIND_CANARY: return "canary";
        case CG_KIND_HONEYTOKEN: return "honeytoken";
        case CG_KIND_WATCHDIR: return "watched-folder";
        default: return "?";
    }
}

inline const char* eventTypeName(uint32_t type) {
    switch (type) {
        case CG_EV_CANARY: return "canary";
        case CG_EV_HONEYTOKEN: return "honeytoken";
        case CG_EV_SPEED: return "speed-check";
        default: return "?";
    }
}

enum class Severity { Info, Warning, Critical };

struct Alert {
    Severity severity = Severity::Info;
    uint64_t when_ns = 0;          // wall clock, ns since 1970
    std::string tag;               // KILLED, ALERT, INTEGRITY, ...
    std::string message;
};

// "tried to write to" when the driver blocked it, "wrote to" when it did not.
inline std::string verbFor(const cg_event& ev) {
    bool blocked = ev.action == CG_ACTION_KILLED;
    switch (ev.op) {
        case CG_OP_WRITE: return blocked ? "tried to write to" : "wrote to";
        case CG_OP_UNLINK: return blocked ? "tried to delete" : "deleted";
        case CG_OP_RENAME: return blocked ? "tried to rename" : "renamed";
        default: return "read";
    }
}

inline Alert alertFromEvent(const cg_event& ev) {
    Alert a;
    bool killed = ev.action == CG_ACTION_KILLED;
    a.severity = killed ? Severity::Critical : Severity::Warning;
    a.when_ns = ev.ts_ns;
    a.tag = killed ? "KILLED" : "ALERT";

    std::string who = std::string(ev.comm) + "[" + std::to_string(ev.pid) + "] uid=" + userText(ev.uid);
    std::string tail = killed ? "  -> operation blocked, process killed" : "";

    switch (ev.type) {
        case CG_EV_SPEED:
            a.message = who + " changed " + std::to_string(ev.count) + " files within " +
                        std::to_string(ev.window_ms) + " ms in " + ev.path + " (last: " + ev.file + ")" +
                        tail;
            break;
        case CG_EV_HONEYTOKEN:
            a.message = who + " " + verbFor(ev) + " honeytoken " + ev.path + tail;
            break;
        default:
            a.message = who + " " + verbFor(ev) + " canary file " + ev.path + tail;
            break;
    }
    return a;
}

}  // namespace cg
