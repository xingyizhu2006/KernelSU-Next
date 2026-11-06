obj-m += touchinj.o

# CI 用法（DDK 容器里 KDIR 已设置）:
#   make -C "$KDIR" M="$PWD" ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
#
# 本地交叉编译（有内核源码/KDIR 时）:
#   make -C /path/to/kernel KDIR=/path/to/kernel ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 M=$PWD modules
