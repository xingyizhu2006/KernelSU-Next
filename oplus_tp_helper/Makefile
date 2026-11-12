obj-m += oplus_tp_helper.o
# IPv6 钩子的验证版本：模块名不同，可以和已加载的旧模块共存，
# 不用重启平板就能测 IPv6 注入。验证通过后把源码合回 oplus_tp_helper。
obj-m += oplus_tp_helper6.o

# CI:
#   make -C "$KDIR" M="$PWD" ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
