# SPDX-License-Identifier: GPL-2.0-only
#
# CanaryGuard - top-level Makefile.   Run "make help" for the list of targets.

KDIR     ?= /lib/modules/$(shell uname -r)/build
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
CXXFLAGS += -Iinclude
LDLIBS   += -pthread

BUILD    := build
TOOLS    := canaryctl canaryd ransim cgdemo
TOOL_BIN := $(addprefix $(BUILD)/,$(TOOLS))
MODULE   := kernel/canaryguard.ko

.PHONY: all kernel tools load unload reload test demo stress clean help

all: kernel tools

# ---- kernel module (C) ------------------------------------------------------

kernel:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel modules

# ---- user-space tools (C++) -------------------------------------------------

tools: $(TOOL_BIN)

$(BUILD)/%: tools/%.cpp tools/cg_common.hpp tools/sha256.hpp include/canaryguard_uapi.h | $(BUILD)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

# ransim and cgdemo share the sandbox helpers
$(BUILD)/ransim $(BUILD)/cgdemo: tools/sandbox.hpp

$(BUILD):
	mkdir -p $(BUILD)

# ---- run it -----------------------------------------------------------------

load: kernel
	@if lsmod | grep -q '^canaryguard '; then echo "canaryguard is already loaded"; \
	else sudo insmod $(MODULE) && echo "canaryguard loaded"; fi

unload:
	@if lsmod | grep -q '^canaryguard '; then sudo rmmod canaryguard && echo "canaryguard unloaded"; \
	else echo "canaryguard is not loaded"; fi

reload: unload load

demo: all load
	sudo $(BUILD)/cgdemo

test: all load
	sudo $(BUILD)/cgdemo --auto

# load and unload the driver 20 times: it must never fail or leak
stress: kernel
	@for i in $$(seq 1 20); do \
		sudo insmod $(MODULE) || exit 1; \
		sudo rmmod canaryguard || exit 1; \
	done; echo "stress: 20 load/unload cycles OK"; sudo dmesg | tail -n 2

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel clean
	rm -rf $(BUILD)

help:
	@echo "make            build the kernel module and the C++ tools"
	@echo "make load       load the driver into the running kernel   (needs sudo)"
	@echo "make unload     remove the driver"
	@echo "make demo       guided live demo (narrated)"
	@echo "make test       automatic end-to-end tests (PASS/FAIL)"
	@echo "make stress     20 load/unload cycles"
	@echo "make clean      remove everything that was built"
