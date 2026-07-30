obj-m += shadowmask_susfs.o

shadowmask_susfs-objs := \
    shadowmask_sus.o \
    syscall_hook.o   \
    proc_filter.o

ccflags-y := \
    -O2 \
    -fstack-protector-strong \
    -DMODULE \
    -I$(src) \
    -Wno-unused-function \
    -Wno-declaration-after-statement
