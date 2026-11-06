# oplus_tp_helper KSU module

KSU/Magisk 模块壳：开机 `service.sh` 加载 `oplus_tp_helper.ko`，并传 `hide=1`
让模块从 `/proc/modules`、`/sys/module` 消失。

## 安装

1. 把 CI 产物 `oplus_tp_helper.ko` 用 `patch_vermagic.py` 改成设备 vermagic；
2. 复制到本目录，文件名 `oplus_tp_helper.ko`；
3. 整个目录打包成 zip（`module.prop` 在 zip 根目录），用 KSU 管理器安装；
4. 重启，或手动 `su -c 'insmod /data/adb/modules/oplus_tp_helper/oplus_tp_helper.ko hide=1'`。

## 注意

- `hide=1` 后 `rmmod` 找不到模块；要重新加载只能重启。
- `KERNEL_SECURITY_CHECK` 在加载时仍会记录 `oplus_tp_helper.ko hash not found`，
  这是加载时事件，隐藏模块列表不会消除。
- 模块目录本身还要走 SUSFS `sus_path` 隐藏。
- 调试期先 `hide=0` 手动加载；确认稳定后再用 `hide=1`。
