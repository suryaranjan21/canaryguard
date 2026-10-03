# Requirements, plan and traceability

This follows the SDLC phases of the course: requirements, design ([ARCHITECTURE.md](ARCHITECTURE.md)), implementation, testing, deployment.

## 1. Problem statement

Ransomware encrypts every file it can reach, quickly, one after another. Ordinary antivirus software often reacts too late because it only recognises *known* programs. We want a defence that reacts to **behaviour**, that **cannot be bypassed from user space**, and that **stops the attacker while it is working**.

## 2. Users

| User | Needs |
|------|-------|
| **Administrator** | protect folders, see what is happening, change the rules, avoid false alarms |
| **Evaluator / student** | run a safe, repeatable demonstration and see PASS/FAIL results |

## 3. Scope

**In scope:** a Linux kernel driver with three detection layers (canary files, speed check, honeytoken), a response (block + kill, or alert only), a reliable alert channel to user space, and C++ tools to operate and demonstrate it.

**Out of scope (future work):** recovering encrypted files, identifying programs by signature, network or remote alerting, a graphical interface, and the other Domain 4 ideas (syscall auditor, rootkit detection, virtual TPM).

## 4. Functional requirements

| ID | Requirement | Implemented in | Verified by (`make test`) |
|----|-------------|----------------|---------------------------|
| FR-1 | The administrator can register bait files (canaries, honeytokens) and watched folders | `cg_table.c`, `canaryctl plant / watch` | Act 2 and 3: `canaryctl plant`, `watch`; "refuses to register the same file twice" |
| FR-2 | A write, delete or rename of a canary is **blocked**, the process is **killed**, and an alert is raised | `cg_hooks.c` (`cg_inspect_*`, `cg_ret_handler`) | "ransim was KILLED by the kernel", "the canary files are untouched", "rm was killed and the canary still exists", "mv was killed and the canary kept its name" |
| FR-3 | Reading a honeytoken raises an alert **without** killing the reader | `cg_hooks.c` | "cat was NOT killed", "the driver raised a honeytoken alert" |
| FR-4 | A process changing more than N different files within T ms in a watched folder is blocked and killed; N and T are configurable | `cg_hooks.c` (`cg_speed_note`) | "only 9 files were encrypted: the 10th file was protected"; "refuses a speed limit of 1 file" |
| FR-5 | A *warn* mode reports without blocking | `cg_mode`, `canaryctl mode` | "warn mode: ransim ran to the end", "the driver only alerted" |
| FR-6 | A safe list exempts named programs | `cg_table.c`, `canaryctl allow` | "an allow-listed 'ransim' finished its run" |
| FR-7 | Alerts reach user space reliably; if the buffer overflows the loss is **counted and reported** | `cg_events.c`, `canaryd` | "200 events raised: 128 kept, 72 counted as dropped" |
| FR-8 | Operator commands: list, statistics, mode, speed limit, safe list, remove, clear, reset | `cg_main.c` (ioctl), `canaryctl` | Act 5 and the extra checks |
| FR-9 | A background monitor shows alerts live, logs them, can run as a daemon, and notices canary files changed *behind* the driver | `canaryd` | "canaryd logged the KILLED alert", "canaryd noticed that a canary file was changed behind the driver's back", "canaryd stopped cleanly on SIGTERM" |
| FR-10 | A safe, repeatable demonstration exists | `ransim`, `cgdemo` | the whole suite; `ransim` refuses folders without the marker |

## 5. Non-functional requirements

| ID | Requirement | How it is met | Evidence |
|----|-------------|---------------|----------|
| NFR-1 | **Performance:** noticeable cost must stay below 1 µs per file open | one atomic read when nothing is registered; spinlock-protected list walk otherwise | measured +0.11 to +0.14 µs per open+close (README, *Testing*) |
| NFR-2 | **Safety:** only root can control it; it can never be pointed at the operating system; it never kills the kernel, `init` or its own tools | `CAP_SYS_ADMIN` check, device mode 0600, refusal to watch `/`, `/usr`, `/etc`, ...; safe list defaults | "a normal user cannot open /dev/canaryguard", "refuses to watch /usr", "refuses to watch /" |
| NFR-3 | **Robustness:** loading and unloading must never fail or leak, even under load | hooks registered last and removed first; all entries released on unload | `make stress` (20 cycles); storm test with unload in the middle |
| NFR-4 | **Portability:** ARM64 and x86-64; Linux 6.8 to 7.0 | no CPU-specific code; generic argument helpers; version guards; size assertions in both languages | compiles without warnings against 6.8, 6.14, 6.17, 7.0 headers; full suite and stress tests run on 6.8 and 7.0 |
| NFR-5 | **Usability:** build and run with simple commands and clear errors | `make`, `make test`, `make demo`; "the driver is not loaded: run sudo make load" | README quick start |
| NFR-6 | **No external dependencies** in the tools | standard library only; own SHA-256 | `g++` and the kernel headers are enough |
| NFR-7 | **Maintainability:** layered, documented code | four small kernel files, shared header, documentation set | [ARCHITECTURE.md](ARCHITECTURE.md) |

## 6. Programme rules and how they are met

| Rule from the course | How CanaryGuard meets it |
|----------------------|--------------------------|
| Only C/C++ | kernel module in C, tools in C++17; no Python, Java or script files; building and running is done with `make` |
| Linux only | a Linux kernel module; developed and tested on Ubuntu 24.04 |
| Linux Device Driver concepts | a loadable module with a **character device**, file operations, ioctl, `poll`, spinlocks and a mutex, a workqueue, sysfs and the device model, module parameters, `copy_to/from_user`, kernel memory allocation |
| Software or hardware architecture | a layered, event-driven design with a clear kernel/user boundary ([ARCHITECTURE.md](ARCHITECTURE.md)) |
| GitHub with structure, source, README, documentation | this repository |
| Completed and uploaded by 5 Oct 2026 | see the plan below |
| 5 to 10 minute evaluation with a GitHub-based demonstration | [DEMO_SCRIPT.md](DEMO_SCRIPT.md): a 5-minute demo run straight from the repository |

*Hardware-specific driver topics from the course (interrupt handlers, GPIO, I2C, SPI) are not applicable: this is a software-security driver and there is no physical device.*

## 7. Use cases

See the use-case diagram in [ARCHITECTURE.md](ARCHITECTURE.md#2-use-cases).

| Use case | Main flow |
|----------|-----------|
| Protect a folder | admin runs `canaryctl plant <folder>` → bait is created → driver registers the folder and the bait |
| Ransomware attack | ransomware opens a canary for writing → driver denies, kills it, queues an alert → monitor prints it |
| Slow or bait-avoiding attack | ransomware changes 10 files in 2 s → driver denies the 10th, kills it, queues an alert |
| Snooping | a program reads `passwords.txt` → driver queues an alert with program, PID, user |
| False alarm | a legitimate bulk operation is stopped → admin uses `mode warn` or `allow <program>` |

## 8. Plan and milestones

Solo project; the plan follows the build order, and each step was tested before the next began.

| # | Milestone | Done when | Date |
|---|-----------|-----------|------|
| M1 | Environment | Ubuntu VM, compilers and kernel headers; a "hello" module loads | 3 Oct |
| M2 | Driver core | `/dev/canaryguard`, decoy table, ioctl, sysfs | 3 Oct |
| M3 | Detection | canary + honeytoken + speed check, block and kill | 3 Oct |
| M4 | Alert pipeline | ring buffer, workqueue, `canaryd` | 3 Oct |
| M5 | Demo and tests | `ransim`, `cgdemo`, 44 checks green, stress and concurrency tests | 3 Oct |
| M6 | Documentation | README, architecture, requirements, setup, demo script, Q&A | 3 to 4 Oct |
| M7 | Validation on the demo machine (Intel/AMD laptop) | `make test` passes there | 4 Oct |
| M8 | Submission | final push to GitHub, repository public | by 5 Oct |

**Version-control strategy:** one `main` branch; small commits that follow the build order; each commit message says *what* and *why*; the tree builds and passes `make test` at every milestone commit.

## 9. Risks

| Risk | Mitigation |
|------|-----------|
| Kernel API changes between versions break the build | version guards; compile-tested against four kernel versions; `make deps` installs the right headers |
| The driver misbehaves and freezes the machine | developed only inside a VM; stress and concurrency tests; hooks registered last, removed first |
| False positives kill a legitimate program | per-folder scope, configurable limit, `warn` mode, safe list; documented trade-off |
| The demo fails on the evaluation machine | `make test` run beforehand; [SAMPLE_RUN.txt](SAMPLE_RUN.txt) as evidence; setup guide with troubleshooting |
| Virtualisation disabled on the demo laptop | checked early; setup guide explains how to enable it |
