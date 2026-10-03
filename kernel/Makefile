# SPDX-License-Identifier: GPL-2.0-only
#
# Kbuild file for the CanaryGuard kernel module.
# Normally you do not run this directly: use "make" in the project root.

obj-m += canaryguard.o
canaryguard-y := cg_main.o cg_table.o cg_hooks.o cg_events.o

# the shared header with the user/kernel contract lives in ../include
ccflags-y := -I$(src)/../include
