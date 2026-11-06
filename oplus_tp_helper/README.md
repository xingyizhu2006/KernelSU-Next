# oplus_tp_helper

触屏注入 LKM，伪装成 OPPO 触屏辅助模块。目标 OPD2508 / 6.6.118，触屏
`/dev/input/event2`（name `touchpanel`）。

## 路径

- `nf_register_net_hook`：`PRE_ROUTING` + `LOCAL_IN`，`NF_IP_PRI_FIRST`
- 只匹配 UDP 61069 + magic `0x31484354`
- `NF_STOLEN` 吃包，环形队列 + workqueue 注入
- 没有 socket、没有 `/proc/net/udp` 条目、没有用户态进程
- `input_class` 没导出：kprobe 拿 `kallsyms_lookup_name`，再找 `input_class`

## 构建

```sh
cd oplus_tp_helper
make -C "$KDIR" M="$PWD" ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules -j"$(nproc)"
llvm-strip -d oplus_tp_helper.ko
```

DDK 产物的 vermagic 是 6.6.127，加载前改成设备实际值：

```sh
python tools/re_drivers/patch_vermagic.py oplus_tp_helper.ko oplus_tp_helper_66118.ko \
  "6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k SMP preempt mod_unload modversions aarch64"
```

## 加载

```sh
adb push oplus_tp_helper_66118.ko /data/adb/modules/oplus_tp_helper/
adb shell su -c 'insmod /data/adb/modules/oplus_tp_helper/oplus_tp_helper_66118.ko'
```

## PC 发包

包格式 18 字节：

```text
u32 magic=0x31484354 | u32 seq | u8 type | u8 contact |
u16 x | u16 y | u16 major | u16 reserved
```

`type`：1=tap，2=down，3=move，4=up。

## 注意

- 模块名/路径/字符串都按 `oplus_tp_helper`，不要再用 `touchinj`。
- OPPO `KERNEL_SECURITY_CHECK` 仍会记录 `ko:[oplus_tp_helper.ko] hash not found`；
  改名只降低可见性，hash 仍是未知模块。
- 后续：token/源 IP、模块加载方式、KSU 模块化、隐藏。
