# Payload: position-independent, no libc; every intercepted syscall runs
# here. GUARDED=1 adds the guarded runtime.
TARGET := payload.bin
ARCH_DIR := arch/aarch64
PATH_SRC := ../path

SRC := $(addprefix logic/, config.c dispatch.c async_io.c integrity.c platform.c libc_shim.c broker_client.c hook_runtime.c fake_ids.c \
	container_state.c union_view.c lazy_layer.c net_view.c \
	clone_notify.c proot_bridge.c proot_mounts.c proot_procfs.c proot_exec.c proot_auxv.c) \
	$(addprefix $(ARCH_DIR)/, entry.S raw_syscall.S syscall_disp.c mini_libc.c \
	reentry_guard.c payload_stack.c stub.c clone_entry.S)
ifeq ($(GUARDED),1)
SRC += $(addprefix logic/, vm_write_guard.c fs_policy.c fd_runtime.c fd_snapshot.c \
	fd_handoff.c fd_receive.c fd_table.c fd_clone.c fd_registry.c fd_guard.c \
	fd_close_queue.c fd_close_exec.c)
CPPFLAGS += -DGUARDED
endif
OBJ := $(patsubst %.S,%.o,$(SRC:.c=.o)) \
	$(addprefix path-build/, path_helpers.o canon_core.o resolve_core.o binding_core.o)

CPPFLAGS += -I. -Iinclude -I$(ARCH_DIR) -I.. -D_GNU_SOURCE
# Optimized: this code runs on every intercepted syscall. No strict aliasing:
# guest buffers and kernel records are reinterpreted in several places.
# x28 is never used: a signal can arrive while a thread is in the payload,
# and the guest's handler runs with the registers of that moment; Go's
# handler takes its g from x28 (arm64), as all its code does.
CFLAGS := -Wall -O2 -g -fno-strict-aliasing -fPIC -nostdlib -fno-stack-protector -fno-builtin \
	-ffixed-x28

all: $(TARGET)

$(TARGET): $(OBJ)
	$(LD) -shared --no-undefined -Bsymbolic -e _start -o $@ $(OBJ)

path-build:
	mkdir -p $@
path-build/%.o: $(PATH_SRC)/%.c | path-build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DNDEBUG -Djoin_paths=sv_path_join -MMD -MP -c $< -o $@
-include path-build/*.d

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
%.o: %.S
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Called by entry.S before it saves the guest's SIMD registers.
$(ARCH_DIR)/reentry_guard.o $(ARCH_DIR)/payload_stack.o logic/fake_ids.o: CFLAGS += -mgeneral-regs-only

$(ARCH_DIR)/entry.o: $(ARCH_DIR)/syscall_nums.h $(ARCH_DIR)/slow_syscalls.inc \
	$(ARCH_DIR)/fd_runtime_syscalls.inc $(ARCH_DIR)/fd_unsupported_syscalls.inc
logic/fd_runtime.o: $(ARCH_DIR)/fd_unsupported_syscalls.inc

clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf path-build
