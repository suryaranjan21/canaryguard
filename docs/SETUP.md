# Setup: getting Linux and running CanaryGuard

CanaryGuard is a Linux **kernel driver**. It must run on Linux, and while you develop or demo it, it should run in a **virtual machine** so that a mistake can never harm your real computer.

**You need:** Ubuntu **24.04 LTS** (any kernel from 6.8 up to 7.0 works), 2 CPUs, 4 GB RAM, 20 GB disk, internet access.

---

## 1. Windows laptop (Intel / AMD)

### Step 0: check that virtualisation is switched on

Open **Task Manager → Performance → CPU**. At the bottom right it must say **Virtualization: Enabled**.
If it says *Disabled*, restart the laptop, open the BIOS/UEFI setup (usually `F2`, `F10`, `Del` or `Esc` at start-up) and enable **Intel VT-x / Virtualization Technology** (on AMD: **SVM Mode**). Then continue.

Also note your Windows edition (**Settings → System → About**): *Home* or *Pro*. It decides which option below fits best.

### Option A (recommended): Multipass

Multipass, from Canonical (the makers of Ubuntu), creates Ubuntu virtual machines from one command.

1. Install it from <https://canonical.com/multipass/install>.
   - **Windows Pro / Enterprise:** choose the **Hyper-V** driver.
   - **Windows Home:** choose the **VirtualBox** driver (the installer will offer to install it).
2. Open **PowerShell** and create the machine:

   ```powershell
   multipass launch 24.04 --name guard --cpus 2 --memory 4G --disk 20G
   multipass shell guard
   ```

   You are now inside Ubuntu. Everything below is typed there.

3. Get the code (the repository is public):

   ```bash
   sudo apt-get update && sudo apt-get install -y git
   git clone https://github.com/suryaranjan21/canaryguard.git
   cd canaryguard
   ```

   If `git clone` does not work (some networks block it), on GitHub press **Code → Download ZIP**, then in PowerShell (not inside the VM):

   ```powershell
   multipass transfer $HOME\Downloads\canaryguard-main.zip guard:/home/ubuntu/
   ```

   and inside the VM: `sudo apt-get install -y unzip && unzip canaryguard-main.zip && cd canaryguard-main`

> **Time limit:** if Option A is not working after about 20 minutes, stop and switch to Option B. Do not spend the day debugging the installer: the project itself needs only about 10 minutes once Ubuntu is running.

### Option B: VirtualBox with the Ubuntu Desktop ISO

Choose this if you want a full Ubuntu desktop on screen.

1. Install **VirtualBox** from <https://www.virtualbox.org/> and download the **Ubuntu 24.04 Desktop ISO** from <https://ubuntu.com/download/desktop> (about 6 GB).
2. Create a new virtual machine: type *Linux / Ubuntu (64-bit)*, **4 GB RAM**, **2 CPUs**, **25 GB** disk, and use the ISO as the installation medium. Install Ubuntu with the defaults.
3. Open a terminal in Ubuntu and get the code as in Option A (step 3).

> A new Ubuntu 24.04 Desktop usually runs a **newer kernel** (6.14, 6.17 or 7.0) than a Multipass machine (6.8). CanaryGuard builds for both; `make deps` installs the headers that match whichever kernel you have.

### Not recommended

- **WSL2:** it uses a Microsoft kernel without the files needed to build and load your own modules.
- **Dual boot:** repartitioning a laptop is risky and unnecessary.

---

## 2. Build and run (inside Ubuntu)

```bash
make deps     # once: build tools + headers of the running kernel (asks for your password)
make          # builds the driver (kernel/canaryguard.ko) and the tools (build/)
make test     # loads the driver, runs the 50 automatic checks
make demo     # the guided live demo
```

**What success looks like:** `make test` ends with

```text
  50 passed, 0 failed
  ALL CHECKS PASSED
```

Useful commands:

| Command | What it does |
|---------|--------------|
| `make load` / `make unload` | load / remove the driver (`sudo` is asked for) |
| `make stress` | 20 load/unload cycles |
| `lsmod \| grep canary` | is the driver loaded? |
| `sudo dmesg \| grep canaryguard` | what the driver wrote to the kernel log |
| `cat /sys/class/canaryguard/canaryguard/stats` | live counters |
| `make clean` | delete everything that was built |

Clean up afterwards: `sudo make unload`. To delete the whole Multipass machine: `multipass delete guard` then `multipass purge`.

---

## 3. Troubleshooting

| Message or problem | Cause and fix |
|--------------------|---------------|
| `/lib/modules/.../build: No such file or directory` | the kernel headers are missing: `make deps` |
| `make: g++: command not found` | `make deps` |
| `insmod: ERROR: could not insert module ...: Invalid module format` | the module was built for a different kernel (for example after a kernel update and reboot): `make clean && make` |
| `insmod: ERROR: ... Key was rejected by service` | **Secure Boot** is on and refuses unsigned modules. Turn Secure Boot off in the VM settings (VirtualBox: *Settings → System* and untick *Enable EFI*, or disable Secure Boot in the VM's firmware) and restart the VM |
| `insmod: ERROR: ... Operation not permitted` | you forgot `sudo` (use `make load`) |
| `canaryd: cannot open /dev/canaryguard: No such file or directory` | the driver is not loaded: `make load` |
| `... Permission denied` from a tool | run it with `sudo` |
| `make test` fails right at the start with *"contains something that is not a demo folder"* | an earlier run was interrupted: `sudo build/canaryctl clear && sudo rm -rf /var/tmp/canaryguard-demo`, then run it again |
| The VM is very slow or will not start | check *Virtualization: Enabled* (step 0); give the VM 4 GB RAM and 2 CPUs; close other heavy programs |
| `module verification failed: signature and/or required key missing - tainting kernel` in `dmesg` | harmless: Ubuntu notes that the module is not signed. The driver works normally |
| `ransim` shows `Killed` | that is the **expected** result: the kernel killed the fake ransomware |
| `rm` or `mv` of a bait file prints `Killed` | also expected: the guard protects its bait files. Run `sudo build/canaryctl clear` first if you really want to delete them |

---

## 4. Verified environments

| Machine | Ubuntu | Kernel | CPU | Result |
|---------|--------|--------|-----|--------|
| Development VM | 24.04.4 LTS | 6.8.0-134-generic | arm64 | 50 / 50 checks pass; stress and concurrency tests pass |
| Development VM, newest kernel | 24.04.4 LTS | 7.0.0-38-generic | arm64 | 50 / 50 checks pass; stress and concurrency tests pass |
| Build check only | 24.04 | 6.14.0-37, 6.17.0-42 headers | arm64 | compiles without warnings |
| Build check only (cross-compiled) | 24.04 | 6.8.0-134 Intel (x86-64) headers | x86-64 | driver and all tools compile without warnings |
