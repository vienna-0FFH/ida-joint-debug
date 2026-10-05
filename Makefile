CC ?= gcc
CPPFLAGS ?= -Iinclude -D_GNU_SOURCE
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
PYTHON ?= python3
KERNEL_BUILD ?= /lib/modules/$(shell uname -r)/build

SHIM := tools/libida_joint_shim.so
SHIM_SOURCES := src/linux_server_shim.c src/wait_entry_x86_64.S
SHIM_PARTS := src/ida90_event_adapter.inc src/parent_resume_semantics.inc src/owner_wait_view.inc
ABI_HEADERS := include/joint_debug_abi.h include/shared_event_reader.h
SMOKE_NAMES := policy_ioctl_smoke policy_event_smoke policy_lifecycle_smoke \
 policy_mmap_smoke policy_command_mailbox_smoke policy_command_exit_smoke \
 policy_stopped_owner_smoke policy_stopped_debugregs_smoke \
 policy_native_resume_boundary_smoke policy_stopped_query_exit_race_smoke \
 policy_owner_wait_context_smoke shared_ring_reader_smoke kernel_tree_ptrace_smoke
SMOKES := $(addprefix tests/,$(SMOKE_NAMES))
FIXTURES := tests/server_ptrace_harness tests/anti_debug_tracee \
 tests/parent_owned_call_tracee tests/parent_owned_exception_tracee tests/nested_mt_tracee

.PHONY: all shim fixtures kernel-smokes test module module-check module-clean clean
all: $(SHIM) $(SMOKES) $(FIXTURES)
shim: $(SHIM)
fixtures: $(FIXTURES)
kernel-smokes: $(SMOKES)

$(SHIM): $(SHIM_SOURCES) $(SHIM_PARTS) $(ABI_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fcf-protection=branch -fPIC -shared \
	  -o $@ $(SHIM_SOURCES) -ldl -pthread

tests/policy_stopped_debugregs_smoke: tests/policy_stopped_debugregs_smoke.c $(ABI_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -no-pie -o $@ $< -pthread

tests/parent_owned_call_tracee: tests/parent_owned_call_tracee.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -no-pie -o $@ $< -pthread

tests/parent_owned_exception_tracee: tests/parent_owned_exception_tracee.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -no-pie -o $@ $< -pthread

tests/%: tests/%.c $(ABI_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -pthread

test: $(SHIM) tests/server_ptrace_harness tests/anti_debug_tracee tests/shared_ring_reader_smoke
	./tests/shared_ring_reader_smoke
	$(PYTHON) tests/test_joint_shim.py

module:
	bash tools/build_kernel_module.sh "$(KERNEL_BUILD)"

module-check:
	$(MAKE) -C "$(KERNEL_BUILD)" M="$(CURDIR)/driver" modules

module-clean:
	$(MAKE) -C "$(KERNEL_BUILD)" M="$(CURDIR)/driver" clean

# Only explicit outputs of this Makefile are removed, never external samples.
clean:
	$(RM) $(SHIM) $(SMOKES) $(FIXTURES)
