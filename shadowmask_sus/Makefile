# Makefile — shadowmask_sus kernel module
# Built in-tree against Ocin4everKernel after main kernel compile.
# workflows.sh runs:
#   make -C out M=$PWD/shadowmask_sus LLVM=1 LLVM_IAS=1 ARCH=arm64 modules

obj-m += shadowmask_sus.o

shadowmask_sus-objs := \
    main.o          \
    syscall_hook.o  \
    proc_filter.o

ccflags-y := \
    -O2 \
    -fstack-protector-strong \
    -DMODULE \
    -I$(src) \
    -Wno-unused-function \
    -Wno-declaration-after-statement
