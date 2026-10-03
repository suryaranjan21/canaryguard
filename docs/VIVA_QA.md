# Questions you may be asked, with plain answers

Use your own words; the answers below are the facts. Where a question sends you to a file, open it and look once: it is the quickest way to remember.

---

## A. The big picture

**1. What does your project do?**
It is a Linux kernel driver that stops ransomware. It plants bait files and a fake passwords file, and it counts how many different files each program changes. A program that touches bait, or changes too many files too fast, is blocked and killed by the kernel. Alerts are shown live by a monitor program.

**2. What is ransomware?**
A malicious program that encrypts the victim's files and demands money for the key. It works fast and goes through folder after folder.

**3. Why in the kernel and not as a normal program?**
Every file operation of every program goes through the kernel, so the driver sees everything and can say "no" at that exact moment. A normal program can be killed or fooled by the attacker, and it only hears about events *after* they happened.

**4. How is it different from an antivirus?**
A classic antivirus compares files with a list of known viruses. CanaryGuard looks at **behaviour** (touching bait, changing many files quickly), so it can catch ransomware it has never seen.

**5. What is a canary file? A honeytoken?**
A canary is a bait file that no real user ever changes (the name comes from the canary that miners took underground: if it fell sick, they knew there was danger). A honeytoken is a fake secret, like a passwords file; anyone who reads it is snooping.

**6. Why three layers?**
They cover each other. Bait files catch ransomware for certain once it touches them. The speed check catches ransomware that avoids the bait. The honeytoken catches thieves who only read. A slow attacker passes the speed check but is still caught at the first bait file.

**7. Where is the "device driver" in this project?**
`kernel/canaryguard.ko` is a loadable kernel module with a **character device**, `/dev/canaryguard`. It implements `open`, `read`, `poll`, `ioctl` and `release`, and it uses the device model (class and sysfs).

**8. Why a character device and not a block or network device?**
It exchanges small commands and a stream of events, not blocks of storage or network packets. A character device is the simple fit.

---

## B. Inside the kernel module

**9. What is a kernel module? How is it loaded?**
Code that is added to the running kernel without rebooting. `insmod` loads it (the kernel runs its `module_init` function, `cg_init`), `rmmod` removes it (`cg_exit`). `lsmod` lists loaded modules.

**10. What are module parameters?**
Settings given at load time, like `insmod canaryguard.ko mode=0`. I have four: `mode`, `speed_check`, `speed_threshold`, `speed_window_ms`. They also appear in `/sys/module/canaryguard/parameters/` and can be changed live.

**11. How do you see every file operation? What is a kprobe?**
A **kprobe** lets a module run its own function when a chosen kernel function is executed. A **kretprobe** does it twice: once on entry and once on return. I attach kretprobes to three kernel permission checks: `security_file_open`, `security_inode_unlink` and `security_inode_rename`.

**12. Why a kretprobe and not just a kprobe?**
On *entry* I can inspect the request and send the kill; on *return* I can change the result to "permission denied" (`-EPERM`). Without the return half, the operation that triggered the alarm would still complete: for example an open with `O_TRUNC` would still empty the file.

**13. Why not patch the system call table? Why not an LSM, fanotify or eBPF?**
The syscall table is read-only and patching it is not supported on modern kernels. A Linux Security Module must be built into the kernel, not loaded as a module. `fanotify` and eBPF are valid alternatives, but the course project is about device drivers, and a kprobe is the supported way for a module to hook a kernel function.

**14. How do you block an operation?**
In the return handler: if my entry handler decided to deny, and the kernel function returned 0 ("allowed"), I overwrite the return register with `-EPERM`. The caller then fails the open, delete or rename exactly as if a security module had refused it. (`cg_ret_handler`, `cg_hooks.c`.)

**15. How do you kill the process?**
`send_sig_info(SIGKILL, SEND_SIG_PRIV, current)`. `current` is the process that is performing the operation. SIGKILL cannot be caught or ignored and ends the whole process.

**16. What is `current`?**
A kernel macro that points to the task (process) that is running on this CPU right now. In the hook, that is the program that made the file request.

**17. Why can't the hook sleep? What does "atomic context" mean?**
The hook runs in the middle of another process's file operation, with preemption disabled. Sleeping there could deadlock the system. So inside the hook I only use spinlocks, atomics and fixed memory; I cannot use `kmalloc(GFP_KERNEL)`, mutexes, or `printk` heavy work.

**18. Why spinlocks and not mutexes?**
A mutex may put the caller to sleep, which is forbidden in the hook. A spinlock makes the CPU wait in a loop for a very short time, which is allowed. I use `spin_lock_irqsave`, which also disables local interrupts, so an interrupt can never try to take a lock that its own CPU already holds.

**19. Which locks do you have?**
`cg_lock` (decoy list and safe list), `cg_speed_lock` (per-process counters), `cg_prod_lock` (writing to the ring buffer): all spinlocks. `cg_read_lock` is a mutex for the *reader* (`read()` is allowed to sleep). Counters are atomics. No two of my locks are ever held together, so there is no deadlock. See the table in `docs/ARCHITECTURE.md`.

**20. How does an alert get to user space?**
The hook copies a 384-byte `struct cg_event` into a **kfifo ring buffer** (128 events) and wakes up the waiting reader. `canaryd` sleeps in `poll()` on `/dev/canaryguard`, then calls `read()` and receives whole events.

**21. What happens if the ring buffer is full?**
The newest event is dropped, and a counter (`dropped`) goes up. `canaryd` compares that counter after each read and prints "N event(s) were lost". The hook must never wait, so dropping is the only safe choice; counting it turns a silent loss into a visible one.

**22. What is the workqueue for?**
The hook is on the path of every file open in the system, so it must be quick. Printing to the kernel log is slow, so the hook only puts the event in a small queue and calls `schedule_work`; a worker thread does the printing later. That is the *top half / bottom half* idea from the course.

**23. What is `ioctl` and why do you use it?**
A way to send a structured command to a driver. I use it to add and remove decoys, change settings, and read statistics. The command numbers are built with `_IOR`, `_IOW`, `_IOWR`, which encode direction, a magic number (0xCA), a command number and the size of the argument.

**24. What are `copy_from_user` and `copy_to_user`?**
The safe way to move data between user memory and kernel memory. A pointer from user space cannot be trusted (it may be invalid or malicious), so the kernel never dereferences it directly. Every ioctl argument goes through these two functions.

**25. Where do you allocate memory in the kernel?**
`kzalloc` for each decoy entry and `kfifo_alloc` for the ring buffer (which uses `kmalloc`), both with `GFP_KERNEL`, which is allowed to sleep, so only in process context (ioctl, module init), never in the hook. Everything is freed on `clear` and on `rmmod`.

**26. How does the driver recognise a canary?**
By **inode**, not by name. When a decoy is registered, the kernel resolves the path (`kern_path`) and I keep the `struct path`, which pins the file so its inode cannot be freed or reused. Comparing inode pointers is immune to relative paths, symlinks and hard links.

**27. How does the speed check work?**
For each process (thread group) I keep a stop-watch and a list of the *different* files it changed (by inode number) in watched folders. If the count reaches the limit (default 10) before the window (default 2 seconds) runs out, the process is blocked and killed. Writing the same file a thousand times counts as one. A fixed table of 32 processes is used because the hook may not allocate memory.

**28. How do you know a file is inside a watched folder?**
`is_subdir(dentry, watched_dentry)` walks up the directory tree from the file and checks whether it passes through the watched folder.

**29. Why is the 10th file protected in the demo?**
The speed check fires while the kernel is *opening* the 10th file, before it truncates it. My return handler turns the open into a failure, so that file is never touched. Only the 9 files before it are lost.

**30. What happens on `rmmod`?**
`cg_exit` first unregisters the kretprobes (when that returns, none of my handlers can run any more), then removes the device, class and cdev, releases all pinned files and frees the buffers. Order matters: stop the hooks before freeing what they use. `make stress` loads and unloads 20 times, and I also unloaded it during heavy file activity.

**31. Why does the module say `MODULE_LICENSE("GPL")`?**
`register_kretprobe` is exported only to GPL modules (`EXPORT_SYMBOL_GPL`). A non-GPL module could not even load, and the kernel would mark itself "tainted".

**32. What if your module has a bug?**
It runs in the kernel with no memory protection, so a bug can crash the whole system. That is why I developed and tested it in a virtual machine only.

**33. Who can use `/dev/canaryguard`?**
Only root: the node has mode 0600 and every ioctl also checks `capable(CAP_SYS_ADMIN)`. Whoever can configure the guard could switch it off.

**34. What is sysfs and what do you use it for?**
A virtual file system that exposes kernel objects as files. `class_create` and `device_create_with_groups` create `/sys/class/canaryguard/canaryguard/`, and its `stats` file shows the counters as text. (The device node in `/dev` is created by `udev` from the same information.)

---

## C. User space (C++)

**35. How do the tools talk to the driver?**
They open `/dev/canaryguard`, call `ioctl` for commands and `read` / `poll` for events. A small C++ class, `cg::Device`, wraps this.

**36. Which C++ features did you use?**
Classes and RAII (`cg::Fd` closes the descriptor automatically), STL containers (`vector`, `map`, `optional`), exceptions, lambdas, `std::filesystem`, threads with `mutex` and `condition_variable` (the integrity watcher in `canaryd`), and virtual functions (`AlertSink`).

**37. What is RAII? Where do you use it?**
"Resource acquisition is initialisation": a resource is owned by an object and released in its destructor, so it is released even if an exception is thrown. `cg::Fd` owns a file descriptor.

**38. What design pattern do you use?**
**Observer** in `canaryd`: an `AlertBus` hands every alert to all registered `AlertSink` objects (console, log file). A new output (e-mail, network) means a new sink class and no change to existing code. `Device` is a **facade**.

**39. How does `canaryd` wait for events and signals together?**
`poll()` on two descriptors: the device and a `signalfd`. SIGINT and SIGTERM are blocked and arrive as readable data on the `signalfd`, so one loop handles both.

**40. How does the daemon mode work?**
The classic recipe: `fork`, `setsid`, `fork` again, `chdir("/")`, redirect the standard descriptors to `/dev/null`, and write a pid file (`/run/canaryd.pid`).

**41. What is the integrity check for?**
Every few seconds a thread re-computes the SHA-256 of each canary file. If one changed or vanished *without* the driver stopping it (for example a write the hooks cannot see), the monitor raises an `INTEGRITY` alert. It is a second line of defence.

**42. How is `ransim` kept harmless?**
It refuses to touch a folder that lacks a marker file created by `ransim --setup`, and `--setup` refuses a folder that already contains other files. Its "encryption" is XOR with a fixed key, so `ransim --restore` brings every file back byte for byte (the tests compare SHA-256 hashes).

---

## D. Testing, performance, limits

**43. How did you test it?**
`make test` runs 44 automatic checks against the real driver: all three layers, warn mode, safe list, delete and rename of bait, a slow attacker, ring-buffer overflow, bad input, permissions, and the monitor. `make stress` does 20 load/unload cycles. I also ran a storm test (8 loops of heavy file activity, attackers being killed repeatedly, decoys rewritten continuously) and unloaded the driver in the middle of it: no crash or kernel warning. The driver compiles without warnings against kernels 6.8, 6.14, 6.17 and 7.0, and all tests were run on 6.8 and 7.0.

**44. Does it slow the system?**
Measured: about 0.1 to 0.14 µs added per `open()` (569 ns to about 680-710 ns for open+close). When nothing is registered the hook does one atomic read and returns.

**45. What are the limitations?**
(1) It limits damage but cannot undo it: files encrypted before the catch stay encrypted. (2) A slow attacker passes the speed check (but not the bait). (3) Bulk work inside a watched folder can look like an attack: there is warn mode and the safe list. (4) The safe list uses process names, which can be imitated. (5) Root can unload the driver. (6) A few write paths, like `truncate(2)` by path, are not hooked; the integrity check covers them. (7) It is a learning prototype, not a commercial product.

**46. Can ransomware simply switch it off?**
Only if it already has root: then it can `rmmod` the module. That is true for any defence that runs on the same machine. In production one would add module signing, kernel lockdown and a remote monitor.

**47. What if a normal program, like a file copy, is killed by mistake?**
That is the trade-off of any behaviour rule. It can be handled with `canaryctl mode warn` (alerts only), `canaryctl allow <name>` (safe list), or a higher limit (`canaryctl speed 30 2000`). It only applies inside the watched folders, never to the system.

**48. How would you improve it?**
Recover files from snapshots, identify programs by hash instead of name, per-user policies, correlate several processes, an eBPF-based variant, and sending alerts over the network.

**49. Does it work on other CPUs and kernel versions?**
The code has no CPU-specific parts (it uses the kernel's generic helpers to read arguments and set the return value) and the shared header is checked for identical size on both sides. It is guarded for API changes between kernel 6.2 and 7.0 and was built against four versions.

**50. Which topics from the course did you apply?**
Kernel modules, a character device with file operations, ioctl, synchronisation (spinlock, mutex, atomics), deferred work (workqueue), the device model and sysfs, `copy_to_user`/`copy_from_user`, kernel memory allocation; and in user space file descriptors, `poll`, signals, a daemon, processes (`fork`, `exec`, `waitpid`), C++ classes, RAII, STL, exceptions, threads, Makefiles, and UML and SDLC for the documentation.

---

## E. Walk-through

**51. Walk me through what happens when `ransim` writes to `Budget_2026.xlsx`.**
`ransim` calls `open(..., O_WRONLY|O_TRUNC)` → the kernel starts opening the file and calls `security_file_open` → my entry handler `cg_entry_open` looks up the inode in the decoy table (spinlock) and finds a canary → `cg_raise` builds the event, counts it, sends SIGKILL to `ransim`, and pushes the event into the ring buffer (waking `canaryd`) → `security_file_open` returns 0, but my return handler changes it to `-EPERM` → the open fails, the file is not truncated, and `ransim` dies when it returns to user space → `canaryd`'s `poll()` wakes up, `read()` returns the event, and the alert is printed.
