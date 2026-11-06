# touchinj LKM

最小 LKM 触屏注入验证。目标 OPD2508 / ColorOS 16 / kernel 6.6.118，触屏
`/dev/input/event2`（name `touchpanel`）。

## 它做什么

加载时在 workqueue 里向 `touchpanel` 注入一次 tap：

- `ABS_MT_SLOT` / `ABS_MT_TRACKING_ID`（由 `input_mt_*` 维护）
- `ABS_MT_POSITION_X/Y`
- `ABS_MT_TOUCH_MAJOR`
- `BTN_TOOL_FINGER` / `BTN_TOUCH`
- `EV_SYN`

本机 `ABS_MT_PRESSURE` 的范围是 `0..0`，所以不发 pressure。坐标默认
`10599,50`（状态栏附近），可用模块参数覆盖。

## 构建

CI 用 `ghcr.io/ylarod/ddk-min:android15-6.6-20260828`，和现有
`ddk-lkm-*.yml` 一致：

```sh
cd touchinj
make -C "$KDIR" M="$PWD" ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules -j"$(nproc)"
llvm-strip -d touchinj.ko
```

产物 vermagic 是 DDK 的 `6.6.127-...`，加载前用
`tools/re_drivers/patch_vermagic.py` 改成设备实际 vermagic：

```sh
python tools/re_drivers/patch_vermagic.py touchinj.ko touchinj_66118.ko \
  "6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k SMP preempt mod_unload modversions aarch64"
```

设备上实际值可用 `cat /sys/module/oplus_gpu_boost/vermagic` 确认（ksuinit
重写后的值）。

## 测试

```sh
adb push touchinj_66118.ko /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/touchinj_66118.ko tap_x=10599 tap_y=50'
adb shell su -c 'dmesg | tail -20'
adb shell su -c 'getevent -l /dev/input/event2'
```

看到 `BTN_TOUCH DOWN/UP` 和 `ABS_MT_POSITION_X/Y` 即成功。

## 下一步

1. 验证 tap 后，加一个字符设备或模块参数触发连续 tap。
2. 加 netfilter `PRE_ROUTING` + `NF_STOLEN` + workqueue，PC 走 UDP。
3. 最后再包成 KSU 模块（`service.sh` 里 `insmod`），不要先塞 init_boot。
