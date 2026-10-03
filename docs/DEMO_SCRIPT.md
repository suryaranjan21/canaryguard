# Demo script (about 5 minutes)

The evaluation is 5 to 10 minutes. This script fits the demo into 5 and leaves time for questions. Words in *italics* are what to say.

## Ten minutes before

1. Start the Ubuntu virtual machine and open a terminal. Make the font large (`Ctrl` + `+`).
2. Go to the project and make sure it is built and the old state is clean:

   ```bash
   cd ~/canaryguard
   make
   sudo build/canaryctl clear 2>/dev/null; sudo pkill canaryd
   ```

3. Run the full test once: `make test`. It must end with **44 passed, 0 failed**.
4. Open the GitHub page of the repository in the browser (the README with the architecture diagram).
5. Leave the terminal ready at the project folder. Do **not** start `canaryd` yourself: `make demo` starts its own monitor.

## The demo

### 0:00 to 1:00: what and why (browser: the README diagram)

*"Ransomware encrypts all your files, one after another, very quickly. Normal antivirus often reacts too late. My project, CanaryGuard, is a Linux kernel driver that stops ransomware while it is working."*

*"Every program must ask the kernel before it touches a file. My driver sits at that gate, so it sees every attempt and cannot be bypassed from user space."*

*"It has three layers: bait files called canaries, a speed check that counts how many files a program changes, and a honeytoken: a fake passwords file that exposes snoopers."*

Point at the diagram: *"The driver is in C, the tools around it are in C++. They talk through one device file, /dev/canaryguard."*

### 1:00 to 1:30: the repository (browser or `ls`)

*"kernel/ is the driver, tools/ is the user-space part, docs/ has the architecture, UML diagrams, requirements and the setup guide."*

### 1:30 to 4:00: the live demo (terminal)

```bash
make demo
```

Press Enter between the acts. At each act:

| Act | What happens | What to say |
|-----|--------------|-------------|
| **1: no protection** | the fake ransomware encrypts all 20 files | *"This is `ransim`, a harmless imitation: it only works in demo folders and its encryption is reversible. Without protection every file is lost."* |
| **2: canary files** | killed at `Budget_2026.xlsx`, 3 files lost | *"I plant bait files. The moment it tries to write to one, the kernel refuses the write and kills the process. The bait is untouched. The 3 files before it are the price: the guard limits damage, it can't undo it."* |
| **3: speed check** | killed at the 10th file, 9 files lost | *"Now a folder with no bait at all. A normal user never changes 10 different files in 2 seconds, so the driver treats that as an attack: behaviour, not a name."* |
| **4: honeytoken** | `cat` reads `passwords.txt`; alert, no kill | *"The file is fake. Nobody honest needs it, so reading it is suspicious. I'm not killing here because harmless tools read files too, but I get the program, the user and the time."* |
| **5: statistics** | counters, entries, sysfs | *"The same numbers are available through ioctl and through the sysfs file."* |

Point at the red alert lines printed by the live monitor: *"Each alert travelled from the kernel through a ring buffer to this monitor."*

### 4:00 to 5:00: show the code (editor or `less`)

Open `kernel/cg_hooks.c` and show three things:

1. **`cg_entry_open`**: *"This runs when the kernel starts to open any file. I look at the file."*
2. **`cg_raise`**: *"If it is an attack I build the event, send SIGKILL..."*
3. **`cg_ret_handler`**: *"...and when the kernel's check returns, I change the answer to 'permission denied', so the file is never even truncated."*

Optionally show `include/canaryguard_uapi.h`: *"This one header is shared by the C driver and the C++ tools, so both always agree on the data layout."*

### After 5:00: questions

Offer: *"The documentation has the architecture, the requirements and the test results."* Open [VIVA_QA.md](VIVA_QA.md) yourself beforehand: it contains answers to the likely questions.

## If you want a manual, two-window demo instead

Window 1:

```bash
sudo build/canaryd
```

Window 2:

```bash
build/ransim --setup /var/tmp/canaryguard-demo/x                  # a demo folder with 20 files
sudo build/canaryctl plant /var/tmp/canaryguard-demo/x            # bait + speed check
sudo build/canaryctl list
build/ransim --attack /var/tmp/canaryguard-demo/x                 # killed at the bait
cat /var/tmp/canaryguard-demo/x/passwords.txt                     # honeytoken alert
sudo build/canaryctl stats
build/ransim --restore /var/tmp/canaryguard-demo/x                # files come back
sudo build/canaryctl clear                                        # stop guarding
```

## Useful commands if asked "show me"

```bash
lsmod | grep canary                                # the driver is loaded
ls -l /dev/canaryguard                             # the character device (root only)
modinfo kernel/canaryguard.ko                      # description, license, parameters
ls /sys/module/canaryguard/parameters/             # mode, speed_check, speed_threshold, speed_window_ms
cat /sys/class/canaryguard/canaryguard/stats       # live statistics
sudo dmesg | grep canaryguard                      # what the driver logged
```

## If something goes wrong

| Problem | Do this |
|---------|---------|
| The driver does not load | `uname -r`, then `make clean && make && make load`. If it still fails, show [SAMPLE_RUN.txt](SAMPLE_RUN.txt) and explain the design from the diagram |
| An act shows `[FAIL]` | `sudo build/canaryctl clear; make unload; make load` and start `make demo` again |
| *"contains something that is not a demo folder"* | `sudo build/canaryctl clear && sudo rm -rf /var/tmp/canaryguard-demo`, then again |
| The VM hangs | restart the VM; keep calm; the GitHub page and the sample run still tell the story |

## Five sentences to remember

1. *Ransomware is fast and does the same thing to many files, and that behaviour is what I detect.*
2. *The driver sits in the kernel, where every file operation must pass, so it cannot be bypassed.*
3. *It attaches to the kernel's permission checks with kretprobes: it inspects on the way in and changes the answer to "denied" on the way out.*
4. *Three layers: bait files, a speed check, and a honeytoken. They cover each other's weaknesses.*
5. *It limits the damage but cannot undo it; and I know exactly where its limits are.*
