#!/system/bin/sh
MODDIR=${0%/*}
[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/oplus_tp_helper.ko" ] || exit 0
insmod "$MODDIR/oplus_tp_helper.ko" hide=1 2>/dev/null
